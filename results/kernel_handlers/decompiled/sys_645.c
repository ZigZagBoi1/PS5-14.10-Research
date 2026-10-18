/* handler_645.bin — REA 6.7.0 / Ghidra 12.1.4, static recovered pseudocode.
 * Original SHA256 c22afc5c7cc3a6c3a1387f51b7dfa46b1ee55bb4b399853fd85ca6e05596c78e.
 * Input zero = 0xffffffff8ac25760; actual target = 0xffffffff8af220e0.
 * Original binary is 512 adjacent JMP trampolines, not 512 implementations.
 * Part 1: analyst-reviewed semantic recovery with inferred types/field names.
 * Part 2: original REA/Ghidra primary-body decompilation.
 * Part 3: REA decompilation of each mapped trampoline in this input.
 * Calling conventions/external prototypes incomplete; not original or buildable C.
 * Actual body bytes are supplemental kernel_text.bin, not original input window.
 */

/* REA evidence: ev_e326e406aa569de360ba62c9cb29aad973c641cc2f683fe09f22df2c896b667d (function_ffffffff8af220e0.json); reconciled with raw instructions. */
/* Shared nosys target 0xffffffff8af220e0; syscall 645, narg=0.
   Names nosys/signal are corroborated only by supplied sysent classification;
   exact helpers remain address-named. */
#include <stdint.h>
#include <stddef.h>
typedef struct { uint8_t pad0[8]; uintptr_t process; } TdNosys;
/* thread.process +0x08; process lock object +0x148. */
extern void call_8ae86a00(void *,int,int,int);
extern void call_8ae86fa0(void *,int,int,int);
extern void call_8ac18ff0(void *,size_t);
extern void call_8af20540(uintptr_t,void *,int,void *);
int handler_645(TdNosys *td, const void *unused_args) {
    void *lock=(void *)(td->process+0x148);
    call_8ae86a00(lock,0,0,0);
    uint8_t event[0x70];
    call_8ac18ff0(event,0x70);
    *(uint32_t *)(event+0x10)=0x0c;
    *(uint32_t *)(event+0x18)=0x00010006;
    call_8af20540(td->process,td,0x0c,event);
    call_8ae86fa0(lock,0,0,0);
    return 0x4e;
    /* Assembly checks global canary 0xffffffff8e2dc310 and calls
       0xffffffff8b0bd6b0 on mismatch; omitted above. */
}

/* ===== PART 2: RAW REA/GHIDRA BODY handler_body_645 0xffffffff8af220e0 =====
 * Evidence: ev_e326e406aa569de360ba62c9cb29aad973c641cc2f683fe09f22df2c896b667d
 * Signature: undefined handler_body_645()
 * Body: {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xffffffff8af220e0", "end": "0xffffffff8af22187"}], "total_bytes": 168, "span_bytes": 168, "non_contiguous": false, "contains_entry": true}
 * Limitations: ["Unresolved computed or indirect flows without target addresses are not represented as reference edges.", "Thunk and external classifications are Ghidra FunctionManager observations; they do not resolve targetless calls.", "Pseudocode and assembly are Ghidra-specific representations, not original source or Hopper-equivalent text.", "Synthetic Ghidra entry-point references without actionable memory sources are omitted."]
 */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_645(long param_1)

{
  code *pcVar1;
  long lVar2;
  undefined1 local_a0 [16];
  undefined4 local_90;
  undefined4 local_88;
  long local_30;
  
  local_30 = _DAT_ffffffff8e2dc310;
  lVar2 = *(long *)(param_1 + 8) + 0x148;
  func_0xffffffff8ae86a00(lVar2,0,0,0);
  func_0xffffffff8ac18ff0(local_a0,0x70);
  local_90 = 0xc;
  local_88 = 0x10006;
  func_0xffffffff8af20540(*(undefined8 *)(param_1 + 8),param_1,0xc,local_a0);
  func_0xffffffff8ae86fa0(lVar2,0,0,0);
  if (_DAT_ffffffff8e2dc310 == local_30) {
    return 0x4e;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* ===== PART 3: ALL 512 ORIGINAL TRAMPOLINES =====
 * Adjacent stubs are not subcommands. No permission checks/argument decoding in JMP-only bodies.
 * Unknown external ABI remains unknown. Ghidra halt_baddata() for unmapped tail
 * destinations is a boundary artifact, not an observed CPU halt or invalid target.
 */

/* Input +0x000, VA 0xffffffff8ac25760, JMP target 0xffffffff8af220e0; Evidence ev_17fdfa8ef08ed6a5e9af3238d28bce4c176ce9643ec09a305875a541ff656045 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af220e0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_645(long param_1)

{
  code *pcVar1;
  long lVar2;
  undefined1 auStack_a0 [16];
  undefined4 uStack_90;
  undefined4 uStack_88;
  long lStack_30;
  
  lStack_30 = _DAT_ffffffff8e2dc310;
  lVar2 = *(long *)(param_1 + 8) + 0x148;
  func_0xffffffff8ae86a00(lVar2,0,0,0);
  func_0xffffffff8ac18ff0(auStack_a0,0x70);
  uStack_90 = 0xc;
  uStack_88 = 0x10006;
  func_0xffffffff8af20540(*(undefined8 *)(param_1 + 8),param_1,0xc,auStack_a0);
  func_0xffffffff8ae86fa0(lVar2,0,0,0);
  if (_DAT_ffffffff8e2dc310 == lStack_30) {
    return 0x4e;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0x008, VA 0xffffffff8ac25768, JMP target 0xffffffff8ad76020; Evidence ev_29b62dd13e3cdab6dd4adda08e070cc16651c4a1b8cbedda891da88a05fcd395 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ad76020); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ad76020(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x010, VA 0xffffffff8ac25770, JMP target 0xffffffff8ad76240; Evidence ev_e4d98a75cf0b40503627df00f658ce7be14553c970b7cfbe7a95620220e5bf41 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ad76240); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ad76240(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x018, VA 0xffffffff8ac25778, JMP target 0xffffffff8ad81e10; Evidence ev_4a95f64e79c6b67d08416b3462c6b50ade3cf77395f3bc94420483f38268e49e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ad81e10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ad81e10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x020, VA 0xffffffff8ac25780, JMP target 0xffffffff8ad82240; Evidence ev_219beee6aaed3a9bc8b75fe2f2c260f21e4d5ceb8c00f7e9945e7e2cfc513cb6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ad82240); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ad82240(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x028, VA 0xffffffff8ac25788, JMP target 0xffffffff8aaef7e0; Evidence ev_098bee3db068dfeb7a53c64a1f55e788edcf446aeffa5477396df421fa79fd53 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aaef7e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aaef7e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x030, VA 0xffffffff8ac25790, JMP target 0xffffffff8ad8e150; Evidence ev_a865cc292dba055b416ba24afcdd1d505f630892db683082c07d8484c4f23c47 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ad8e150); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ad8e150(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x038, VA 0xffffffff8ac25798, JMP target 0xffffffff8ad952b0; Evidence ev_dfc570de7c129df9728d7b205c05a75cc1a5e39022caf4dc8f42b36e28d20029 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ad952b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ad952b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x040, VA 0xffffffff8ac257a0, JMP target 0xffffffff8ada5aa0; Evidence ev_da44e743b4c64c5e8782b5faf08cc788f8a590082be8234cf457a4540ded1d90 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ada5aa0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ada5aa0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x048, VA 0xffffffff8ac257a8, JMP target 0xffffffff8ada5ad0; Evidence ev_828a050b3da3973bf4e688c3ff15120b638f0baf638aaccb26c21100282c49da */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ada5ad0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ada5ad0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x050, VA 0xffffffff8ac257b0, JMP target 0xffffffff8ada5af0; Evidence ev_b68107695619c304c5e74417576f193c3503ea84aa0b8432f654071cffe05e10 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ada5af0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ada5af0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x058, VA 0xffffffff8ac257b8, JMP target 0xffffffff8adac340; Evidence ev_224433465121ea055a07f63e3d85b28b4eee1f96ea1a9c215c5aa3d296bc006b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adac340); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adac340(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x060, VA 0xffffffff8ac257c0, JMP target 0xffffffff8adb05c0; Evidence ev_adcab9526f9c126f0ea0b07c15c4993256cc48aa3ec6328d2928a78e3ace02a8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adb05c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adb05c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x068, VA 0xffffffff8ac257c8, JMP target 0xffffffff8adb2810; Evidence ev_136cb08faf36d92d1eef98fe26de24148879f1423102e13141dc8defec452a1a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adb2810); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adb2810(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x070, VA 0xffffffff8ac257d0, JMP target 0xffffffff8adb2b60; Evidence ev_a9e159c13297f3f73c7839243504a9464786337ac807f568b7728c60a402f286 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adb2b60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adb2b60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x078, VA 0xffffffff8ac257d8, JMP target 0xffffffff8aecce20; Evidence ev_d4353d3a19e3f676c4cb8734d9a192d34456eb84ed6c5f42608a3420d4a10cad */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aecce20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aecce20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x080, VA 0xffffffff8ac257e0, JMP target 0xffffffff8adb3f90; Evidence ev_40e5d10107bd7b7ec4d1d1b9921b9652ae3ef02c0c1062cc3851cb9ecc0952cf */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adb3f90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adb3f90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x088, VA 0xffffffff8ac257e8, JMP target 0xffffffff8adc9790; Evidence ev_068588ac5f884a19350479454024e9eaece85a55c9a994d585c85154a406399a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adc9790); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adc9790(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x090, VA 0xffffffff8ac257f0, JMP target 0xffffffff8b5a7240; Evidence ev_685375b9fb4141257a1528c3aab5356b58b1810266dab3f2ee54271293a2c08d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5a7240); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5a7240(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x098, VA 0xffffffff8ac257f8, JMP target 0xffffffff8b671390; Evidence ev_4be1846c443f1f5330de3ffa7bf6c9d1d24a3857391c501936ddb497e01d014c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b671390); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b671390(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0a0, VA 0xffffffff8ac25800, JMP target 0xffffffff8aeac000; Evidence ev_f0c3156e1e2d5b4e10db87dca2b26047f9fbe333458d618bc9190dace13a71e0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeac000); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeac000(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0a8, VA 0xffffffff8ac25808, JMP target 0xffffffff8aeac560; Evidence ev_990da0e295120cc02527bcbf4854370f26f7ce3d680bdb1cc4334a4416aa3359 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeac560); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeac560(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0b0, VA 0xffffffff8ac25810, JMP target 0xffffffff8b2b6e00; Evidence ev_996e3fa6dde3aded5141c75232db6fd4974e7c4e478f1ab1d26610df945d7c32 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b6e00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b6e00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0b8, VA 0xffffffff8ac25818, JMP target 0xffffffff8b0ebf00; Evidence ev_b888db244a4d1331bc62f05b032adfc436fb93ea407f49e342ab0ff1c025e505 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0ebf00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0ebf00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0c0, VA 0xffffffff8ac25820, JMP target 0xffffffff8b5a8290; Evidence ev_df594462bbeb56741a7423597321698b044b24cac04b80ca1ec7a3e6a88380e7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5a8290); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5a8290(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0c8, VA 0xffffffff8ac25828, JMP target 0xffffffff8b2b8550; Evidence ev_91825a8ceb13468b103f8d4ee7235d31f9b3873a7bb30cff6652b4f75eb0d181 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b8550); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b8550(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0d0, VA 0xffffffff8ac25830, JMP target 0xffffffff8b2b6b20; Evidence ev_f3b6da5b36d6a705b0da6c40fe4d1d6d8b81c0c3a33cfdd37445f01ba5429510 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b6b20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b6b20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0d8, VA 0xffffffff8ac25838, JMP target 0xffffffff8b2b9b40; Evidence ev_beee92554301c359b91cfc832ed928aaabdaa1c38332b7165740580376dfd0d0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9b40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9b40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0e0, VA 0xffffffff8ac25840, JMP target 0xffffffff8aef29e0; Evidence ev_1dccd028ad4ac0905ff72d55963a360037a4361bfb1b04031b50615b1bbefb87 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef29e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef29e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0e8, VA 0xffffffff8ac25848, JMP target 0xffffffff8aef21e0; Evidence ev_85622998db8652769b437443a1af4dc0b2731c5dabdbbf30f6ecf9f4cdfa6695 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef21e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef21e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0f0, VA 0xffffffff8ac25850, JMP target 0xffffffff8aef28d0; Evidence ev_d73feb2fb8f67f2d7c4bb0dbecda8f3551e4971448b00798ebc606208db25f64 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef28d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef28d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x0f8, VA 0xffffffff8ac25858, JMP target 0xffffffff8aef1080; Evidence ev_fd06c56c130f97e64dc49d9cbaa7575c29b2c2ccc8bf1b09d28150db1a936847 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef1080); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef1080(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x100, VA 0xffffffff8ac25860, JMP target 0xffffffff8aef3310; Evidence ev_d3b4fe25cf95fc13ad360e3078e71697b99bd2e49d428f98bce399613aa7c4bd */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef3310); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef3310(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x108, VA 0xffffffff8ac25868, JMP target 0xffffffff8aef3030; Evidence ev_f91749d4597f70a5f1e72d07c6c08427f7c6b9d15d2b26a91e4ac3ffe27f7cc7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef3030); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef3030(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x110, VA 0xffffffff8ac25870, JMP target 0xffffffff8b2b8be0; Evidence ev_70925d8978e3a72f106c6c604ac6ed327dfa5aef5e39c22f92de6b6bb8f3c0d2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b8be0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b8be0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x118, VA 0xffffffff8ac25878, JMP target 0xffffffff8b2b95b0; Evidence ev_aa697f184b46c6b604e03c2b76c51d4ba84b676cc5886e0d95258bdfdc3abe32 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b95b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b95b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x120, VA 0xffffffff8ac25880, JMP target 0xffffffff8b2b9760; Evidence ev_f5ee1eb09aaac4d487adf9531b85e8aae31cc4d59dff2c93c3ab055bc1518804 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9760); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9760(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x128, VA 0xffffffff8ac25888, JMP target 0xffffffff8b2b5d20; Evidence ev_eb8f7e3685b5e9012bdd27ff2045f15fc26fc468b1db1ef20a93e66f026ec27c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b5d20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b5d20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x130, VA 0xffffffff8ac25890, JMP target 0xffffffff8af1f5b0; Evidence ev_335d73dc3eff18440ad5b9853bb3d344e84595994f36b9086bf85e3ccab950b3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1f5b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1f5b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x138, VA 0xffffffff8ac25898, JMP target 0xffffffff8b0e9d80; Evidence ev_f4913b0be7e5fa181f9aac6d103cdd346656253905c72b5d89dd3186e5975851 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0e9d80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0e9d80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x140, VA 0xffffffff8ac258a0, JMP target 0xffffffff8b1c2d90; Evidence ev_a40fef480b12afe7557b6300f685cc48ba001e1a5b9833752355c6213a2c20ee */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1c2d90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1c2d90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x148, VA 0xffffffff8ac258a8, JMP target 0xffffffff8ae1e4d0; Evidence ev_59afb451744271888e4dce32a483fbcf7ed0af69241140f95300f345cc2ed72c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae1e4d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae1e4d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x150, VA 0xffffffff8ac258b0, JMP target 0xffffffff8af1f400; Evidence ev_98cae3630ac4a6a81d58353709a2c737c0cb8ef923035ff971a0bb028e164012 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1f400); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1f400(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x158, VA 0xffffffff8ac258b8, JMP target 0xffffffff8aeacf40; Evidence ev_3929adbbe14a0e1d8a5eb8cc5eaef73cff4fb9ace4205592606c40dccf80f6e0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeacf40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeacf40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x160, VA 0xffffffff8ac258c0, JMP target 0xffffffff8b1a4810; Evidence ev_57a4aee2dc222508be52dd50b696db004e4a0bfb2ebe3eece537151506d07348 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1a4810); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1a4810(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x168, VA 0xffffffff8ac258c8, JMP target 0xffffffff8b2bc490; Evidence ev_79253f4c3417998dc959d282b523602071e97187b1d43f5087c64bfa6394230c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bc490); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bc490(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x170, VA 0xffffffff8ac258d0, JMP target 0xffffffff8b0a2dc0; Evidence ev_cbfc3772379dc726cb3c2381b334f12837927958e64b4e22493118c18dfa98bf */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0a2dc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0a2dc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x178, VA 0xffffffff8ac258d8, JMP target 0xffffffff8b478af0; Evidence ev_ccc508b49e60042b052f41b6b670f9e06d6b8ee4245978c1eaa2d2f11a3187d8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b478af0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b478af0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x180, VA 0xffffffff8ac258e0, JMP target 0xffffffff8b478bb0; Evidence ev_0112e02eb18b41745b8064bb3da6cbaa76835185e8cf6281af5c6420f8bffc2b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b478bb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b478bb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x188, VA 0xffffffff8ac258e8, JMP target 0xffffffff8b478d20; Evidence ev_2d74b284760d236759bab7312e39908f9372f088aed8a84240c9e39a879750a4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b478d20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b478d20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x190, VA 0xffffffff8ac258f0, JMP target 0xffffffff8b478e00; Evidence ev_3edd76ab7964e287c2dc77d166aa99e8151a00bd0e657a9325feb5c90c44d6e1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b478e00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b478e00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x198, VA 0xffffffff8ac258f8, JMP target 0xffffffff8b478ec0; Evidence ev_78b38a54727eabe3fc7aa9b89b1840f020d88c8d973b9120d24140896b9158dd */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b478ec0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b478ec0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1a0, VA 0xffffffff8ac25900, JMP target 0xffffffff8b07ccc0; Evidence ev_855721897d26b35122d3f4b6c0da2d3d256ae75778476b9a275c0ad64797605b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07ccc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07ccc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1a8, VA 0xffffffff8ac25908, JMP target 0xffffffff8b07ca20; Evidence ev_163af64e3812fb7b3c6d1828fb0ac4aca3b01937fa63e07e8f746a97a5e4d3ec */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07ca20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07ca20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1b0, VA 0xffffffff8ac25910, JMP target 0xffffffff8b0e99f0; Evidence ev_e994b25da50f10502080a503c18d04e5049fcb7b119bb087ad0f2d0e63887d1e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0e99f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0e99f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1b8, VA 0xffffffff8ac25918, JMP target 0xffffffff8b0e9a40; Evidence ev_eab2d4a594025a7a70feef445a05c35bccb3b9906edfcd47d6b5eac4e56ae550 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0e9a40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0e9a40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1c0, VA 0xffffffff8ac25920, JMP target 0xffffffff8b0e9dc0; Evidence ev_406b5da39277140b20dbd1cf6c6379c6d7ad1e134040b498ddc6891069b717ef */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0e9dc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0e9dc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1c8, VA 0xffffffff8ac25928, JMP target 0xffffffff8aeae4b0; Evidence ev_4f319f381ae0dba6d1f633444ec665c2163ec95a09076e825b58deef6f3fe62a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeae4b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeae4b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1d0, VA 0xffffffff8ac25930, JMP target 0xffffffff8b2bb430; Evidence ev_7d40bd19462be61b23171ee6a1035e84d83a883de5caac6a010b72c382e4460c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bb430); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bb430(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1d8, VA 0xffffffff8ac25938, JMP target 0xffffffff8ae5ff80; Evidence ev_9edf84c566a866369d0dbd8dc07f465a375a13741e3ba78d28ad2acc7b116e6b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5ff80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5ff80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1e0, VA 0xffffffff8ac25940, JMP target 0xffffffff8aeef8f0; Evidence ev_2dc426e4901c993a6268c19965f709282952a0cacc90d9c6a1a51852123826f0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeef8f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeef8f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1e8, VA 0xffffffff8ac25948, JMP target 0xffffffff8aef1260; Evidence ev_9ee9f3e2278db2b3975f7bc6125ca2cd87e065f46b1758f5278a9628dca35987 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef1260); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef1260(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1f0, VA 0xffffffff8ac25950, JMP target 0xffffffff8aeefce0; Evidence ev_5c98cf50ef6b3afdf46d383eeb3899f5ee031d7e21528a9bc0b9706c627c4b4e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeefce0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeefce0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x1f8, VA 0xffffffff8ac25958, JMP target 0xffffffff8ae5fcf0; Evidence ev_eae160112020ce3c348614b4e634d48a825ed5f50ad248cebac860b3a940d5f7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5fcf0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5fcf0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x200, VA 0xffffffff8ac25960, JMP target 0xffffffff8aeefd00; Evidence ev_77d441d539978ee00858b13c96410d337fcbc0faba6a02f13d322db9146de965 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeefd00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeefd00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x208, VA 0xffffffff8ac25968, JMP target 0xffffffff8aeefe00; Evidence ev_4b2f84313a0d084f5425aab442a33035df25d940a4e7f253cf71a748e9584ecf */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeefe00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeefe00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x210, VA 0xffffffff8ac25970, JMP target 0xffffffff8aef0480; Evidence ev_21653e95e272e8b74b9a0054917ebf8cc13a8481bfb1e748f20e851eeca3a229 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef0480); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef0480(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x218, VA 0xffffffff8ac25978, JMP target 0xffffffff8aef2bc0; Evidence ev_79672c0bae2df491f22554d761d3a0c1d65c57e4841ef0851a403662f519c66a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef2bc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef2bc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x220, VA 0xffffffff8ac25980, JMP target 0xffffffff8aef07d0; Evidence ev_3dbfbcf3e7a3bb3c085fb900c62de4540236ebc32d419c48a89df56ead9157db */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef07d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef07d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x228, VA 0xffffffff8ac25988, JMP target 0xffffffff8aeefae0; Evidence ev_a23fab155a9a7874491e0fe3ab235384c951b116ee3a35bf31f8b257864e212c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeefae0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeefae0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x230, VA 0xffffffff8ac25990, JMP target 0xffffffff8b0ec140; Evidence ev_f26b830138eb8d6e081e2ed739208226a98aaa7ba71b845fdf3b6c49f35be78f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0ec140); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0ec140(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x238, VA 0xffffffff8ac25998, JMP target 0xffffffff8b07c800; Evidence ev_4e630140b665ad2880e0bb774716cc7e50684d532fc16f44246ec5fd00f0481c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07c800); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07c800(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x240, VA 0xffffffff8ac259a0, JMP target 0xffffffff8ae61ba0; Evidence ev_7fb9f024f4d5269b89f9c9c3fcd7fe58628f4898abce932a763ebcd38b2135d8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae61ba0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae61ba0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x248, VA 0xffffffff8ac259a8, JMP target 0xffffffff8aef2cd0; Evidence ev_d3588edae02b9b06019df7e92affcfd91bdf37ac23f41158826e4948ef5e6a13 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef2cd0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef2cd0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x250, VA 0xffffffff8ac259b0, JMP target 0xffffffff8aeac2c0; Evidence ev_fe386cf650ef6bac3882a617e08b37f1638fda2f68225cc268b37a1c854edd85 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeac2c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeac2c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x258, VA 0xffffffff8ac259b8, JMP target 0xffffffff8aeac8e0; Evidence ev_76f56dca4839c50a3a2e35d6dca3d03df4bc43ab7f367fe0108947948c68aa34 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeac8e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeac8e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x260, VA 0xffffffff8ac259c0, JMP target 0xffffffff8b07c8d0; Evidence ev_d7bfd2ddce8fa873d3c00e732ed658a79c6eb2320560c436b95179ee8f44f100 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07c8d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07c8d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x268, VA 0xffffffff8ac259c8, JMP target 0xffffffff8b2b9d40; Evidence ev_7e514c16bf176e28db71670f8e85712a403804d1ceced21f1f5f31832fb915cf */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9d40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9d40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x270, VA 0xffffffff8ac259d0, JMP target 0xffffffff8aeefe70; Evidence ev_0b4196602ccd38656a63689481a489e9cfa1a42c9db89cf1a573f1b9b6fe8305 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeefe70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeefe70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x278, VA 0xffffffff8ac259d8, JMP target 0xffffffff8b2bb450; Evidence ev_f0ca7adc2a3b05a20cdbf09101634e99d63682aef22af77db1faf51be7301ceb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bb450); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bb450(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x280, VA 0xffffffff8ac259e0, JMP target 0xffffffff8b0ee590; Evidence ev_803c9dcb981c62ed5491188043052fa86556b019acf3f5b143a879cc22dcf317 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0ee590); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0ee590(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x288, VA 0xffffffff8ac259e8, JMP target 0xffffffff8aef1b30; Evidence ev_40acfba2a351c3fff0de7c7a57105be81730a56a858d558f2d4c11b36056d114 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef1b30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef1b30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x290, VA 0xffffffff8ac259f0, JMP target 0xffffffff8aef2af0; Evidence ev_0024d1350adc352b7ae7056fc2e1e9fbe056dc08721b2349a941f8648e54af6a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef2af0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef2af0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x298, VA 0xffffffff8ac259f8, JMP target 0xffffffff8aef1720; Evidence ev_092807e0c4fd4b965892d83bddb458e3359dc396b17c200d534af9ba0cff9d18 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef1720); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef1720(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2a0, VA 0xffffffff8ac25a00, JMP target 0xffffffff8b2bb8e0; Evidence ev_9db634e1306012639001d5f194e0bfdc851c4837e2b4871f1997b54b33bd323b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bb8e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bb8e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2a8, VA 0xffffffff8ac25a08, JMP target 0xffffffff8b2bbbc0; Evidence ev_08229d251c76e6d9d0e626b6ab917ebc99e29f02d7605de9b9c3e72419f0f386 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bbbc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bbbc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2b0, VA 0xffffffff8ac25a10, JMP target 0xffffffff8b2ba310; Evidence ev_a8cc414969170758b5768c22ffb089f66381d9379e7fc6fd9dedbab0accaf675 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2ba310); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2ba310(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2b8, VA 0xffffffff8ac25a18, JMP target 0xffffffff8ae3b030; Evidence ev_b547920f38723a280eaaebbf6611c64ae4a37a6a3f70eb2ad2a25e3acff5e1f6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae3b030); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae3b030(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2c0, VA 0xffffffff8ac25a20, JMP target 0xffffffff8b2b8e20; Evidence ev_dabced251defb8a4fe564bf97d459485a95ce9b8fe3ace0769760dcfc9cb4144 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b8e20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b8e20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2c8, VA 0xffffffff8ac25a28, JMP target 0xffffffff8b0ec150; Evidence ev_68312c49ae903314153cbcf4a442760f6c7199c8428591cebdab7b3df7a208c0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0ec150); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0ec150(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2d0, VA 0xffffffff8ac25a30, JMP target 0xffffffff8b2b9260; Evidence ev_5871596e2a58a06ba16cf3b23dfa2c39881d86a71998b0e64a52fee56cb09d36 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9260); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9260(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2d8, VA 0xffffffff8ac25a38, JMP target 0xffffffff8b2b9310; Evidence ev_8170b3badb8becdc7e25072a8341f834d600ec1554dd1461042a0a15225db99f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9310); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9310(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2e0, VA 0xffffffff8ac25a40, JMP target 0xffffffff8b0ec3e0; Evidence ev_e2f8572ad85644f40e98052a33d8ad51b7d592c1e58fbb1fcea14718c092f5e1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0ec3e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0ec3e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2e8, VA 0xffffffff8ac25a48, JMP target 0xffffffff8ae613e0; Evidence ev_24f885fb5c3c0c66edd6f54f0765b8fd129435868b6ec2e26541c0812dcc47fc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae613e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae613e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2f0, VA 0xffffffff8ac25a50, JMP target 0xffffffff8ae60c30; Evidence ev_a5d9dfc0545a6ffeb9acf2c448351eb1d481bc25fec2d61c917a53d651d04c48 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae60c30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae60c30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x2f8, VA 0xffffffff8ac25a58, JMP target 0xffffffff8b2bbbe0; Evidence ev_b320f20c3fa02c02421d11b98f8d6f19396f2b0f543ea1caa78ac0d4f92b46d4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bbbe0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bbbe0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x300, VA 0xffffffff8ac25a60, JMP target 0xffffffff8af181e0; Evidence ev_44ba851f3ca601c80669c7db07959b9356a8c74cdeda5276c686cf32aba29d99 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af181e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af181e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x308, VA 0xffffffff8ac25a68, JMP target 0xffffffff8b479450; Evidence ev_bf69fcf0a20f5f65aff2debe98c8d555b32f552b4140443b66820e193facd77c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b479450); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b479450(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x310, VA 0xffffffff8ac25a70, JMP target 0xffffffff8b479710; Evidence ev_8d03624aa78b02be306cc74686fdd49eb8b273b3e749e26cf471b17928cf55e5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b479710); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b479710(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x318, VA 0xffffffff8ac25a78, JMP target 0xffffffff8b2ba8e0; Evidence ev_7b84fb0348586aa4c19ec84c829b8a82587303a13e4ba9f1c96628c74ebdbb1d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2ba8e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2ba8e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x320, VA 0xffffffff8ac25a80, JMP target 0xffffffff8aeae550; Evidence ev_0680896e850abe40f15743270ad7b8663a50f2f4009c377c12baad11adecd198 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeae550); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeae550(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x328, VA 0xffffffff8ac25a88, JMP target 0xffffffff8b2bc810; Evidence ev_10d847309a1b498cebfe19f2653d7172508a32e2852b81b63f18e461c9331b2b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bc810); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bc810(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x330, VA 0xffffffff8ac25a90, JMP target 0xffffffff8b2bc820; Evidence ev_c482075b947ddbde1ea7c825511872384285678ff6ecddbdd6589061c6944cbd */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bc820); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bc820(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x338, VA 0xffffffff8ac25a98, JMP target 0xffffffff8b07b670; Evidence ev_9a05c236b42dfaeb63f081ae77450e2cdb69a6f935e40520f731275494aae24f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07b670); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07b670(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x340, VA 0xffffffff8ac25aa0, JMP target 0xffffffff8b07bd20; Evidence ev_f8460c5ff47c4ff87bb6dde680120150020e472b2adf6b68dda46983f263281e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07bd20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07bd20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x348, VA 0xffffffff8ac25aa8, JMP target 0xffffffff8b07c030; Evidence ev_7ae3d66e793f20657551881e025ba08c089ec15e53a92194c9b0b245c167c3e6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07c030); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07c030(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x350, VA 0xffffffff8ac25ab0, JMP target 0xffffffff8b07d570; Evidence ev_3ce9b8f4f7ca7803adfadbf3edbe43aba452de1026fe76d4527c9b263e7dd0b8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07d570); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07d570(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x358, VA 0xffffffff8ac25ab8, JMP target 0xffffffff8b07dfa0; Evidence ev_dc108d2b06a917e138ab56e784ced82ca5b7d6e9298318f89f1ed3b956982074 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07dfa0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07dfa0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x360, VA 0xffffffff8ac25ac0, JMP target 0xffffffff8b07dfb0; Evidence ev_27b40175cd27df8cc57fc36a892f3809c426f66a7a0e7c05f43c6aae5448de95 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07dfb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07dfb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x368, VA 0xffffffff8ac25ac8, JMP target 0xffffffff8b07e1d0; Evidence ev_01e93645c3f3f64e1c541b2d4f46047bbb212efe76a6b18c1dcfe896a9b4f8cb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07e1d0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong sub_6be1d0(long param_1,uint *param_2)

{
  long lVar1;
  long lVar2;
  int *piVar3;
  long lVar4;
  code *pcVar5;
  undefined8 uVar6;
  uint uVar7;
  ulong uVar8;
  undefined8 *in_GS_OFFSET;
  undefined1 auStack_58 [32];
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  lVar4 = *(long *)(param_1 + 8);
  uVar7 = *param_2;
  lVar2 = lVar4 + 0x148;
  func_0xffffffff8ae86a00(lVar2,0,0,0);
  if (((2 < (long)(int)uVar7) && (lVar4 = *(long *)(lVar4 + 0x3b8), uVar7 < 0x20 && lVar4 != 0)) &&
     (lVar4 = *(long *)(lVar4 + 0x20 + (long)(int)uVar7 * 8), lVar4 != 0)) {
    lVar1 = lVar4 + 0x18;
    func_0xffffffff8ae86a00(lVar1,0,0,0);
    if ((*(byte *)(lVar4 + 0x98) & 1) == 0) {
      func_0xffffffff8ae86fa0(lVar2,0,0,0);
      *(int *)(lVar4 + 0x9c) = *(int *)(lVar4 + 0x9c) + 1;
      pcVar5 = *(code **)(&DAT_ffffffff8e2d5848 + (long)*(int *)(lVar4 + 0xa8) * 0x28);
      if (0x3a5 < (-(long)pcVar5 - 0x753d8ff8U >> 3 | -(long)pcVar5 << 0x3d)) {
        func_0xffffffff8ae0f8c0(0xffffffff8cbb7440,pcVar5);
      }
      uVar7 = (*pcVar5)(lVar4,auStack_58);
      piVar3 = (int *)(lVar4 + 0x9c);
      *piVar3 = *piVar3 + -1;
      uVar8 = (ulong)uVar7;
      if ((*piVar3 == 0) && ((*(byte *)(lVar4 + 0x98) & 2) != 0)) {
        func_0xffffffff8b5c6910(lVar4);
      }
      func_0xffffffff8ae86fa0(lVar1,0,0,0);
      if (uVar7 == 0) {
        uVar6 = *(undefined8 *)(param_2 + 2);
        func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
        uVar8 = func_0xffffffff8ac191d0(auStack_58,uVar6,0x20);
      }
      goto LAB_ffffffff8b07e336;
    }
    func_0xffffffff8ae86fa0(lVar1,0,0,0);
  }
  func_0xffffffff8ae86fa0(lVar2,0,0,0);
  uVar8 = 0x16;
LAB_ffffffff8b07e336:
  if (_DAT_ffffffff8e2dc310 == lStack_38) {
    return uVar8;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar5 = (code *)invalidInstructionException();
  (*pcVar5)();
}



/* Input +0x370, VA 0xffffffff8ac25ad0, JMP target 0xffffffff8b07e370; Evidence ev_6df2b4a66350fc71bcd953195d88db91dfc3e5fd570830535d0ead13bd80c9b8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07e370); register/stack arguments unchanged. */

undefined8 sub_6be370(long param_1,uint *param_2)

{
  long lVar1;
  uint uVar2;
  long lVar3;
  undefined8 uVar4;
  
  lVar3 = *(long *)(param_1 + 8);
  uVar2 = *param_2;
  lVar1 = lVar3 + 0x148;
  func_0xffffffff8ae86a00(lVar1,0,0,0);
  uVar4 = 0x16;
  if (((2 < (long)(int)uVar2) && (lVar3 = *(long *)(lVar3 + 0x3b8), uVar2 < 0x20 && lVar3 != 0)) &&
     (lVar3 = *(long *)(lVar3 + 0x20 + (long)(int)uVar2 * 8), lVar3 != 0)) {
    func_0xffffffff8ae86a00(lVar3 + 0x18,0,0,0);
    if ((*(byte *)(lVar3 + 0x98) & 1) == 0) {
      uVar4 = 0;
      *(long *)(param_1 + 0x408) = (long)*(int *)(lVar3 + 0xa4);
    }
    func_0xffffffff8ae86fa0(lVar3 + 0x18,0,0,0);
  }
  func_0xffffffff8ae86fa0(lVar1,0,0,0);
  return uVar4;
}



/* Input +0x378, VA 0xffffffff8ac25ad8, JMP target 0xffffffff8b07c4e0; Evidence ev_363ecbe96c04a000eef45f5858c82104fbc7abd2c379e9c52e5db20c3c3b56c4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07c4e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07c4e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x380, VA 0xffffffff8ac25ae0, JMP target 0xffffffff8b671ab0; Evidence ev_067cda69a3710f76d40758f1c35ed071afdd7b03749116bfc6e50aa1a94b6733 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b671ab0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b671ab0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x388, VA 0xffffffff8ac25ae8, JMP target 0xffffffff8b2bc390; Evidence ev_f6df6b8a7525af080b9d472b35a7d3c4a75b3ff8319bc68ee4476805008b8733 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bc390); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bc390(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x390, VA 0xffffffff8ac25af0, JMP target 0xffffffff8aeac4e0; Evidence ev_bfadb06e0760c3602cec6749987ae3675e7f7417ba33c1dc26d65a52dc2a719d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeac4e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeac4e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x398, VA 0xffffffff8ac25af8, JMP target 0xffffffff8aeacc70; Evidence ev_d1c83bc82457cb1965e61d537a6a9c14b169a6e7589346db78e3df5440013806 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeacc70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeacc70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3a0, VA 0xffffffff8ac25b00, JMP target 0xffffffff8b53e960; Evidence ev_d4bacc94b0dd2c08a71a6e88e14413cc26a8644a398a9cd92d9e6a3c7834c034 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53e960); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53e960(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3a8, VA 0xffffffff8ac25b08, JMP target 0xffffffff8b479580; Evidence ev_600ebb93378d420e0671e9bd880e5599e1d6cc62cd8aab924e6dab6541140fc2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b479580); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b479580(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3b0, VA 0xffffffff8ac25b10, JMP target 0xffffffff8b479690; Evidence ev_6163cb64f8f2d43c76e3814ab101249fcad4fcc8b975cd60adf19cd6133f94b6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b479690); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b479690(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3b8, VA 0xffffffff8ac25b18, JMP target 0xffffffff8af63a60; Evidence ev_af476f82c3e75aa3807b560f9bc7d2537f9c033b3db4699426c5eb721a92c32c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af63a60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af63a60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3c0, VA 0xffffffff8ac25b20, JMP target 0xffffffff8af63b50; Evidence ev_a0ad2a9eae2f5fa40be0c022a1f06930382508ae7a6180ccef611067ce2d400a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af63b50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af63b50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3c8, VA 0xffffffff8ac25b28, JMP target 0xffffffff8af63c60; Evidence ev_e0e6349c6ba1bf0e6db52cfba0c9af42b5ecb650fde898b6f0aeb8b8c180009c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af63c60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af63c60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3d0, VA 0xffffffff8ac25b30, JMP target 0xffffffff8af63d80; Evidence ev_70605fc4b3e8cc4de298dc5cdc737207570f989b13c27806e99bad17356b369b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af63d80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af63d80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3d8, VA 0xffffffff8ac25b38, JMP target 0xffffffff8af63e70; Evidence ev_d6751c358edf49d96531ffa296e9382c03e472c3a2e31d2320fa9a2e45fa8132 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af63e70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af63e70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3e0, VA 0xffffffff8ac25b40, JMP target 0xffffffff8af63e90; Evidence ev_0ae58e14091a879f0d3147c281df0d630cadd1d1a89550d4888ca067700ffc52 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af63e90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af63e90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3e8, VA 0xffffffff8ac25b48, JMP target 0xffffffff8af63ef0; Evidence ev_91bea27ef05fe26bba6049cf19e3eec744e90b916f450510aab827ea49dfe69a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af63ef0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af63ef0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3f0, VA 0xffffffff8ac25b50, JMP target 0xffffffff8af63f50; Evidence ev_d09475262231ee7da5a6e4c346ca760e49ac950b768b7611e46c63518cc911bf */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af63f50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af63f50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x3f8, VA 0xffffffff8ac25b58, JMP target 0xffffffff8af1ddc0; Evidence ev_1a637550c1c64c1655018a1aa3049a2aa639f8721839a77d6472afa7fdfb2a1c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1ddc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1ddc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x400, VA 0xffffffff8ac25b60, JMP target 0xffffffff8af1ed70; Evidence ev_ac5d66ef46e52054a9441c5685818601fb838d5a068f3f456667e1e13f2f7794 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1ed70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1ed70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x408, VA 0xffffffff8ac25b68, JMP target 0xffffffff8af1ec90; Evidence ev_d5fab6a810d477c1effe364ab469d8c19ec3cdde58c36cae551cb774ea4808ec */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1ec90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1ec90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x410, VA 0xffffffff8ac25b70, JMP target 0xffffffff8af1e550; Evidence ev_c93409c172613d2f365330c2c6e7c3c1ba6fe0378ce4c3534006549b87382801 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1e550); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1e550(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x418, VA 0xffffffff8ac25b78, JMP target 0xffffffff8af1e680; Evidence ev_bc98c69a9d7ef994909979ad6ae75a7ea6742322a9028b2f039add73b13c0ead */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1e680); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1e680(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x420, VA 0xffffffff8ac25b80, JMP target 0xffffffff8b47bd80; Evidence ev_fda80d471af20cffb6de580ef85aa1964a5f2116ac998068fc4f1995fbbf0f37 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47bd80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47bd80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x428, VA 0xffffffff8ac25b88, JMP target 0xffffffff8b1f40e0; Evidence ev_5caf59f8e1e380bcb9381495f6b81b560ec36e8af4f74059c7225a805d26bf92 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1f40e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1f40e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x430, VA 0xffffffff8ac25b90, JMP target 0xffffffff8b2b6120; Evidence ev_0682c51fbe7e90487b25329c8950a41217bf20247e55fc549448cd1aa8467c5a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b6120); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b6120(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x438, VA 0xffffffff8ac25b98, JMP target 0xffffffff8b602f00; Evidence ev_36b3b32c372c3060fdef7647e5e218e1f6b449d07f94f8e97147ce1635b792d5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b602f00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b602f00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x440, VA 0xffffffff8ac25ba0, JMP target 0xffffffff8b603010; Evidence ev_40776b331f16dcf1e08d5c859f7c859f9ddfea02cbc1731b3ce3f22d09c0e5b4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b603010); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b603010(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x448, VA 0xffffffff8ac25ba8, JMP target 0xffffffff8b603170; Evidence ev_cc9e8c9183adc0388530821af0609c2ab615aca17e3d0e7e3b8e84d1a8d2027f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b603170); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b603170(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x450, VA 0xffffffff8ac25bb0, JMP target 0xffffffff8b6034a0; Evidence ev_c5ef197fa19237974ce0fe85a3338ff4f84320f961861902bfdd0a7ddae16514 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b6034a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b6034a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x458, VA 0xffffffff8ac25bb8, JMP target 0xffffffff8b602760; Evidence ev_498de9690b3579ee856953e4f936ec22877c4c7271a66bc4659a1137e0db6df3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b602760); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b602760(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x460, VA 0xffffffff8ac25bc0, JMP target 0xffffffff8b602b90; Evidence ev_621333191a02073f8f1a428d3c49fb4381f7fdec09317117aae263fac4899ffb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b602b90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b602b90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x468, VA 0xffffffff8ac25bc8, JMP target 0xffffffff8b602bc0; Evidence ev_a5ba4eb0ee1fe2dfe0e45e6291384da5e3be1a3a4c023fc8eceb0c7501689e33 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b602bc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b602bc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x470, VA 0xffffffff8ac25bd0, JMP target 0xffffffff8b6034c0; Evidence ev_fe977b1d91a74b40d84030e88ef281587a36a9889eb154c0e67e16e55287e5c4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b6034c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b6034c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x478, VA 0xffffffff8ac25bd8, JMP target 0xffffffff8b603620; Evidence ev_1461f98c9bf443c36ea1a7ccc65bee9d1e2a095912534defdd2405abd56bcd11 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b603620); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b603620(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x480, VA 0xffffffff8ac25be0, JMP target 0xffffffff8af1d0c0; Evidence ev_7b494be367c8bfda51e5c1cc3aa3d081d666efbbcc0ebbb447db8f18ef6418cf */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1d0c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1d0c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x488, VA 0xffffffff8ac25be8, JMP target 0xffffffff8b3c7280; Evidence ev_0db76193d44c98460b0d8cee7a529d3f0baf4a8fe5bc5171bc9f35ad24fa19f2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3c7280); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3c7280(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x490, VA 0xffffffff8ac25bf0, JMP target 0xffffffff8b5f7860; Evidence ev_514c36e45a99d6ebe1c79dd65ccd80c0e62074e60a611fcea77a60e2a761d953 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5f7860); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5f7860(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x498, VA 0xffffffff8ac25bf8, JMP target 0xffffffff8b5f7970; Evidence ev_5ea81d6877edd9482d53d596c47fc0f99c4ba55215553ff7e59ac0d5735e6e91 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5f7970); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5f7970(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4a0, VA 0xffffffff8ac25c00, JMP target 0xffffffff8b5f7a20; Evidence ev_385a47839049371000c0a84e88d7559217177e1d3c62c3c41b5dd5992e7b3763 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5f7a20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5f7a20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4a8, VA 0xffffffff8ac25c08, JMP target 0xffffffff8af1deb0; Evidence ev_f32ae992bf6caae5a7b7b3a3fc11465a35d0bb6bbd8ceab5e930624d3af623c2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1deb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1deb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4b0, VA 0xffffffff8ac25c10, JMP target 0xffffffff8adf7cf0; Evidence ev_6392eda60ffa1e4a1b0b547022ea871e7f2d49dd69eadf368a8ebff58e5269b5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf7cf0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adf7cf0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4b8, VA 0xffffffff8ac25c18, JMP target 0xffffffff8adf83f0; Evidence ev_0c85670b888bc71eb8657f6cddf2e1fd4cc5d3f645e34defce8c663e4a36f898 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf83f0); register/stack arguments unchanged. */

undefined8 sub_4383f0(undefined8 param_1,long *param_2)

{
  func_0xffffffff8ad3ed80();
  if (*param_2 != 0) {
    func_0xffffffff8ac19720(*param_2,1);
    func_0xffffffff8ad3e2f0(param_1,*param_2,0x7fffffff,0,0);
  }
  sub_438440(param_1);
  return 0;
}



/* Input +0x4c0, VA 0xffffffff8ac25c20, JMP target 0xffffffff8adf83c0; Evidence ev_45aa761923395a2bdccfe2c623b20cebc73519d1b9ba61a91a94b16eb3c3c782 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf83c0); register/stack arguments unchanged. */

undefined8 sub_4383c0(long param_1,undefined8 *param_2)

{
  int iVar1;
  undefined8 uVar2;
  
  iVar1 = func_0xffffffff8ac19720(*param_2,*(undefined4 *)(param_1 + 0x9c));
  uVar2 = 0xe;
  if (iVar1 != -1) {
    uVar2 = 0;
  }
  return uVar2;
}



/* Input +0x4c8, VA 0xffffffff8ac25c28, JMP target 0xffffffff8adf8560; Evidence ev_397b4260debafb7b116fd32314adc9f910b8276620dc316f180740abc6be95ed */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf8560); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_438560(long param_1,long *param_2)

{
  uint uVar1;
  code *pcVar2;
  long lVar3;
  long lVar4;
  undefined8 uVar5;
  undefined1 auStack_a8 [16];
  uint uStack_98;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  undefined4 uStack_88;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  lVar3 = *(long *)(param_1 + 8);
  func_0xffffffff8ac18ff0(auStack_a8,0x70);
  uStack_98 = *(uint *)(param_2 + 1);
  uStack_90 = 0x10007;
  uStack_8c = *(undefined4 *)(lVar3 + 0xbc);
  uStack_88 = *(undefined4 *)(*(long *)(param_1 + 0x140) + 8);
  if (*param_2 == -1) {
    uVar5 = 0x16;
    if (0x80 < uStack_98) goto LAB_ffffffff8adf86c3;
    lVar4 = lVar3 + 0x148;
    func_0xffffffff8ae86a00(lVar4,0,0,0);
    lVar3 = *(long *)(lVar3 + 0x10);
    uVar5 = 3;
    if (lVar3 != 0) {
      do {
        if (lVar3 != param_1) {
          if ((int)param_2[1] == 0) {
            uVar5 = 0;
            break;
          }
          func_0xffffffff8af21280(lVar3,(int)param_2[1],auStack_a8);
          uVar5 = 0;
        }
        lVar3 = *(long *)(lVar3 + 0x10);
      } while (lVar3 != 0);
    }
  }
  else {
    lVar3 = func_0xffffffff8b552420();
    if (lVar3 == 0) {
      uVar5 = 3;
      goto LAB_ffffffff8adf86c3;
    }
    uVar1 = *(uint *)(param_2 + 1);
    uVar5 = 0;
    if ((uVar1 != 0) && (uVar5 = 0x16, uVar1 < 0x81)) {
      func_0xffffffff8af21280(lVar3,uVar1,auStack_a8);
      uVar5 = 0;
    }
    lVar4 = *(long *)(lVar3 + 8) + 0x148;
  }
  func_0xffffffff8ae86fa0(lVar4,0,0,0);
LAB_ffffffff8adf86c3:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return uVar5;
}



/* Input +0x4d0, VA 0xffffffff8ac25c30, JMP target 0xffffffff8b6033f0; Evidence ev_b7c9dde210db9042e79ac3e7d85ddd57e64eb9a742198e547eb483985cc44f5b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b6033f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b6033f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4d8, VA 0xffffffff8ac25c38, JMP target 0xffffffff8adf88c0; Evidence ev_d0968a194d5bb66ccd538b90896403fe3ccd745c50dd9cda95d00b6433c4e667 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf88c0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_4388c0(long *param_1,long *param_2)

{
  code *pcVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  long lVar5;
  long lVar6;
  int iStack_60;
  long lStack_58;
  long lStack_50;
  long lStack_48;
  long lStack_40;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  if (*param_2 == 0) {
    uVar3 = *(uint *)((long)param_1 + 0xec);
    if ((uVar3 & 0x80000) != 0) {
LAB_ffffffff8adf8965:
      *(uint *)((long)param_1 + 0xec) = uVar3 & 0xfff7ffff;
      iVar2 = 0;
      goto LAB_ffffffff8adf8a7f;
    }
    lVar6 = param_1[1];
    iStack_60 = 0;
LAB_ffffffff8adf89ab:
    lVar5 = lVar6 + 0x148;
    iVar4 = 0;
    func_0xffffffff8ae86a00(lVar5,0,0,0);
    if ((*(byte *)((long)param_1 + 0xe6) & 0x10) == 0) {
      iVar4 = func_0xffffffff8b5c6260
                        (param_1,lVar6 + 0x130,0x1000,0xffffffff8bcd1b02,
                         iStack_60 * _DAT_ffffffff8e2e03d0,0,0x100);
    }
  }
  else {
    iVar2 = func_0xffffffff8ad3e910(*param_2,&lStack_58);
    if (iVar2 != 0) goto LAB_ffffffff8adf8a7f;
    uVar3 = *(uint *)((long)param_1 + 0xec);
    if ((uVar3 & 0x80000) != 0) goto LAB_ffffffff8adf8965;
    lVar6 = param_1[1];
    if (lStack_58 != 0 || lStack_50 != 0) {
      lStack_48 = lStack_58;
      lStack_40 = lStack_50 / 1000;
      iStack_60 = func_0xffffffff8b626c80(&lStack_48);
      goto LAB_ffffffff8adf89ab;
    }
    lVar5 = lVar6 + 0x148;
    iStack_60 = 0;
    func_0xffffffff8ae86a00(lVar5,0,0,0);
    iVar4 = 0x23;
  }
  if ((*(byte *)((long)param_1 + 0xe6) & 0x10) == 0) {
    func_0xffffffff8ae86fa0(lVar5,0,0,0);
    iVar2 = 0x3c;
    if (iVar4 != 0x23) {
      iVar2 = 4;
      if (iStack_60 == 0) {
        iVar2 = iVar4;
      }
      if (iVar4 != -1) {
        iVar2 = iVar4;
      }
    }
  }
  else {
    func_0xffffffff8ae878b0(param_1,0,0xffffffff8bcd1b07,0x299);
    *(byte *)((long)param_1 + 0xe6) = *(byte *)((long)param_1 + 0xe6) & 0xef;
    func_0xffffffff8ae87520(*param_1 + 0x18,0,0,0);
    func_0xffffffff8ae86fa0(lVar5,0,0,0);
    iVar2 = 0;
  }
LAB_ffffffff8adf8a7f:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return iVar2;
}



/* Input +0x4e0, VA 0xffffffff8ac25c40, JMP target 0xffffffff8adf8ab0; Evidence ev_94c67cf5cca6e90a24380a0e5521dac6cc6f0d60f311d7468390991b1307839d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf8ab0); register/stack arguments unchanged. */

undefined8 sub_438ab0(long param_1,long *param_2)

{
  long lVar1;
  long *plVar2;
  undefined8 uVar3;
  
  if (*param_2 == (long)*(int *)(param_1 + 0x9c)) {
    *(byte *)(param_1 + 0xee) = *(byte *)(param_1 + 0xee) | 8;
    uVar3 = 0;
  }
  else {
    lVar1 = *(long *)(param_1 + 8);
    plVar2 = (long *)func_0xffffffff8b552420(*param_2,*(undefined4 *)(lVar1 + 0xbc));
    if (plVar2 == (long *)0x0) {
      uVar3 = 3;
    }
    else {
      uVar3 = 0;
      func_0xffffffff8ae878b0(plVar2,0,0xffffffff8bcd1b07,0x2b9);
      *(byte *)((long)plVar2 + 0xe6) = *(byte *)((long)plVar2 + 0xe6) | 0x10;
      func_0xffffffff8ae87520(*plVar2 + 0x18,0,0,0);
      func_0xffffffff8b5c6910(plVar2);
      func_0xffffffff8ae86fa0(lVar1 + 0x148,0,0,0);
    }
  }
  return uVar3;
}



/* Input +0x4e8, VA 0xffffffff8ac25c48, JMP target 0xffffffff8af12c20; Evidence ev_5e04f5ad94dd778fd287c3519e303124f2db69dcda3d937a90f6d47433a883a4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12c20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12c20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4f0, VA 0xffffffff8ac25c50, JMP target 0xffffffff8adf7de0; Evidence ev_18b24ddf8964795890c3758fa2442d4e21f36b11049325af52de8bdcec0e26bc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf7de0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adf7de0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x4f8, VA 0xffffffff8ac25c58, JMP target 0xffffffff8af1fc20; Evidence ev_81c7d5f82441a6cfd01dabe4e5b425235dec72422ad4200f5b550bb49d74205b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1fc20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1fc20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x500, VA 0xffffffff8ac25c60, JMP target 0xffffffff8adf8b60; Evidence ev_4a011c1b55824beef883fad93078cfdb1f90ae53426d9a2b71603c6e32e5699e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf8b60); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_438b60(long param_1,int *param_2)

{
  long lVar1;
  code *pcVar2;
  int iVar3;
  int iVar4;
  long lVar5;
  undefined8 *in_GS_OFFSET;
  undefined1 auStack_58 [32];
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  func_0xffffffff8ac18ff0(auStack_58,0x20);
  lVar1 = *(long *)(param_2 + 2);
  if (lVar1 != 0) {
    func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd1a084,0);
    iVar3 = func_0xffffffff8ac19900(lVar1,auStack_58,0x20,0);
    if (iVar3 != 0) goto LAB_ffffffff8adf8c6c;
  }
  lVar1 = *(long *)(param_1 + 8);
  if (*param_2 == -1) {
    func_0xffffffff8b317b70(lVar1 + 0x5e4,auStack_58,0x20);
    iVar3 = 0;
  }
  else {
    lVar5 = func_0xffffffff8b552420(*param_2,*(undefined4 *)(lVar1 + 0xbc));
    if (lVar5 == 0) {
      iVar3 = 3;
    }
    else {
      func_0xffffffff8b317b70(lVar5 + 0x294,auStack_58,0x20);
      func_0xffffffff8b078000(lVar5);
      iVar3 = 0;
      func_0xffffffff8ae86fa0(lVar1 + 0x148,0,0,0);
      iVar4 = func_0xffffffff8b4c78d0();
      if (iVar4 != 0) {
        func_0xffffffff8aa65940
                  (*(undefined4 *)(lVar1 + 0xbc),*(undefined4 *)(lVar5 + 0x9c),lVar5 + 0x294);
      }
    }
  }
LAB_ffffffff8adf8c6c:
  if (_DAT_ffffffff8e2dc310 == lStack_38) {
    return iVar3;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* Input +0x508, VA 0xffffffff8ac25c68, JMP target 0xffffffff8ae60400; Evidence ev_dd0f0c3130678ce46ae00f2c0167d122e5414d1532617e411476ecde3894ae60 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae60400); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae60400(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x510, VA 0xffffffff8ac25c70, JMP target 0xffffffff8aeac120; Evidence ev_195d403b3df631530469702fd05b7aaaf29258591c679afd23cdc943cccee2b0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeac120); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeac120(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x518, VA 0xffffffff8ac25c78, JMP target 0xffffffff8aeac740; Evidence ev_eeef80d0c870e67602edd0d756a6399ade9bb25b84d4d1a83c1fa633d57d97f0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeac740); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeac740(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x520, VA 0xffffffff8ac25c80, JMP target 0xffffffff8b4783c0; Evidence ev_e8f88b5fddb818b639d1ee329f62f47d857216559041b24858d3327f425817f1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4783c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4783c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x528, VA 0xffffffff8ac25c88, JMP target 0xffffffff8b2b8ab0; Evidence ev_bdfb2843da546923e3a6a3cec189efd0240b2b56320168dc46a6d2fd446b6f11 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b8ab0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b8ab0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x530, VA 0xffffffff8ac25c90, JMP target 0xffffffff8b2bafa0; Evidence ev_98d833b3f0b94750d0816d19ecd666673bfa50f7468d196be5b1ab4fc89ce823 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bafa0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bafa0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x538, VA 0xffffffff8ac25c98, JMP target 0xffffffff8aeacf20; Evidence ev_d58391bd57823904cf419fcf5998c74468a5c0ab5f63e122d97beb6b5434942c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeacf20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeacf20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x540, VA 0xffffffff8ac25ca0, JMP target 0xffffffff8adf86f0; Evidence ev_9f7805e12a40aae100272408313a81a8e0e082fb97e67b723b403627f218927b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf86f0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_4386f0(long param_1,undefined4 *param_2)

{
  uint uVar1;
  code *pcVar2;
  int iVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  long *in_GS_OFFSET;
  undefined1 auStack_a8 [16];
  undefined4 uStack_98;
  undefined4 uStack_90;
  undefined4 uStack_8c;
  undefined4 uStack_88;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  lVar6 = *in_GS_OFFSET;
  if ((*(byte *)(lVar6 + 0xef) & 1) != 0) {
    func_0xffffffff8ae044e0(param_2[4]);
  }
  func_0xffffffff8ac18ff0(auStack_a8,0x70);
  uStack_98 = param_2[4];
  uStack_90 = 0x10007;
  uStack_8c = *(undefined4 *)(*(long *)(param_1 + 8) + 0xbc);
  uStack_88 = *(undefined4 *)(*(long *)(param_1 + 0x140) + 8);
  if (*(long *)(param_2 + 2) == -1) {
    lVar5 = func_0xffffffff8aefc170(*param_2);
    if (lVar5 == 0) goto LAB_ffffffff8adf8818;
    if ((*(byte *)(lVar6 + 0xef) & 1) != 0) {
      func_0xffffffff8ae04430(lVar5);
    }
    iVar3 = func_0xffffffff8ac6ab20(param_1,lVar5,param_2[4]);
    if ((iVar3 == 0) && (iVar3 = 0x16, (uint)param_2[4] < 0x81)) {
      iVar3 = 3;
      for (lVar6 = *(long *)(lVar5 + 0x10); lVar6 != 0; lVar6 = *(long *)(lVar6 + 0x10)) {
        if (lVar6 != param_1) {
          if (param_2[4] == 0) {
            iVar3 = 0;
            break;
          }
          func_0xffffffff8af21280(lVar6,param_2[4],auStack_a8);
          iVar3 = 0;
        }
      }
    }
  }
  else {
    lVar4 = func_0xffffffff8b552420(*(long *)(param_2 + 2),*param_2);
    if (lVar4 == 0) {
LAB_ffffffff8adf8818:
      iVar3 = 3;
      goto LAB_ffffffff8adf8842;
    }
    lVar5 = *(long *)(lVar4 + 8);
    if ((*(byte *)(lVar6 + 0xef) & 1) != 0) {
      func_0xffffffff8ae04430(lVar5);
    }
    iVar3 = func_0xffffffff8ac6ab20(param_1,lVar5,param_2[4]);
    uVar1 = param_2[4];
    if (uVar1 != 0) {
      if (uVar1 < 0x81) {
        func_0xffffffff8af21280(lVar4,uVar1,auStack_a8);
      }
      else {
        iVar3 = 0x16;
      }
    }
  }
  func_0xffffffff8ae86fa0(lVar5 + 0x148,0,0,0);
LAB_ffffffff8adf8842:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return iVar3;
}



/* Input +0x548, VA 0xffffffff8ac25ca8, JMP target 0xffffffff8b1cd740; Evidence ev_8062fa9f3c7af1ef255acb0376f0e3a7256deb5dc7eec2aa679d1fb5ee5e88b9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1cd740); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1cd740(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x550, VA 0xffffffff8ac25cb0, JMP target 0xffffffff8b1cdbd0; Evidence ev_8a73f9b08ee4aa99906fce08a09b5ced10d9f3bf4f6466093c9be1d9feba355c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1cdbd0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1cdbd0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x558, VA 0xffffffff8ac25cb8, JMP target 0xffffffff8b1fd830; Evidence ev_47936c8ea22df815dcbddf61ae16b53409aecfc24da529f11cf4eb0e12e71648 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1fd830); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1fd830(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x560, VA 0xffffffff8ac25cc0, JMP target 0xffffffff8b1fde60; Evidence ev_6298c0e74c0a4e0a2732f5db72cda9632febe38c2cae088e56ac91059f811e06 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1fde60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1fde60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x568, VA 0xffffffff8ac25cc8, JMP target 0xffffffff8b1fe320; Evidence ev_db66eaebf2156297581a496c83433a36053560bb4fd67c9457b5315258dc3abd */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1fe320); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1fe320(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x570, VA 0xffffffff8ac25cd0, JMP target 0xffffffff8b2b6e50; Evidence ev_b584b0b4d59383724d887369666730fd7c3ef3614aae1a7d1f772fc2e7f13926 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b6e50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b6e50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x578, VA 0xffffffff8ac25cd8, JMP target 0xffffffff8ae5b0b0; Evidence ev_b11d145c5eb74d34194f6526e6f70539ffff74128a548a0b08e89d3820a211ec */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b0b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b0b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x580, VA 0xffffffff8ac25ce0, JMP target 0xffffffff8aead3c0; Evidence ev_33d1fd023d03e186416a72cb063c1b09873b09cb68fc51cdb869c316eaf7b520 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aead3c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aead3c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x588, VA 0xffffffff8ac25ce8, JMP target 0xffffffff8b4b0040; Evidence ev_2ba6f36309380aa7987eb2de932a0c377b71af3eaa642329dd407ac17bc500e6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4b0040); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4b0040(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x590, VA 0xffffffff8ac25cf0, JMP target 0xffffffff8b0c5880; Evidence ev_8216ee1c2e0b696d6862a09c247a9758b2cb6f382b7723e2731df000a18cfe3b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0c5880); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0c5880(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x598, VA 0xffffffff8ac25cf8, JMP target 0xffffffff8b0c5c60; Evidence ev_6bedc1518c9241f1cbfd6462236a4aaef8d32cc9ee585139d91d066a54b60b0c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0c5c60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0c5c60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5a0, VA 0xffffffff8ac25d00, JMP target 0xffffffff8aeb65f0; Evidence ev_2fca2f41e8ceb83108142f6d6c8f14e25fe50aa36676dc51a31a7bea9a6965f5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeb65f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeb65f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5a8, VA 0xffffffff8ac25d08, JMP target 0xffffffff8aeb6a70; Evidence ev_4fecce793e65920918a0b5cd8a376ac4f4af68611e4b9b38244b4df6d0d971ca */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeb6a70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeb6a70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5b0, VA 0xffffffff8ac25d10, JMP target 0xffffffff8b56fa80; Evidence ev_d895fce9c6edea767737a4adf4ed383952f04a5855f11c5e4d50af646dce64f8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b56fa80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b56fa80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5b8, VA 0xffffffff8ac25d18, JMP target 0xffffffff8b56fcf0; Evidence ev_f2ca34fc69f7fcbbf86af99631b1f2002650075a5ef2d6fdfa2a3cd8f49cafc9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b56fcf0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b56fcf0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5c0, VA 0xffffffff8ac25d20, JMP target 0xffffffff8b570330; Evidence ev_56767acd8b73a364dd1416df67cb3c137f9502671d06a65c2c22676c31cfb508 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b570330); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b570330(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5c8, VA 0xffffffff8ac25d28, JMP target 0xffffffff8b570490; Evidence ev_dbcbf8c887524320a49ddcd173424f965ed7488e7ffbc0d21971acfb4ced652b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b570490); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b570490(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5d0, VA 0xffffffff8ac25d30, JMP target 0xffffffff8b56fe50; Evidence ev_a2a7be0ee214b52730dcebe910fa090cd0715ec753e49967047f58a0952e2bb1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b56fe50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b56fe50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5d8, VA 0xffffffff8ac25d38, JMP target 0xffffffff8b570030; Evidence ev_cfc440db33805677a24371b534e6aeae61b09ed8e3fe572057b47f9f56efe5ba */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b570030); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b570030(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5e0, VA 0xffffffff8ac25d40, JMP target 0xffffffff8b570150; Evidence ev_0a52d9ea61004f7bec47b8963fb3fb86f4112b910435a92e2fa722de3859bc40 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b570150); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b570150(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5e8, VA 0xffffffff8ac25d48, JMP target 0xffffffff8b5701d0; Evidence ev_0e17c6bb130fd4f03004d7166c8e5cc9b9250400a68d41f4fa55e0056251c85a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5701d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5701d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5f0, VA 0xffffffff8ac25d50, JMP target 0xffffffff8b570280; Evidence ev_80a158a6dfbeb66003e07510ea6e0c5c4793c6d42fd9b54f24de8dcc47d38ba1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b570280); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b570280(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x5f8, VA 0xffffffff8ac25d58, JMP target 0xffffffff8b47a540; Evidence ev_1c165e02c41bae44af8cd8f5ceda867fa62961762175289a991d0c40377725f7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47a540); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47a540(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x600, VA 0xffffffff8ac25d60, JMP target 0xffffffff8b47be60; Evidence ev_6d2ac8d54bd4e53ec0b406e91e91a51fa9a05ad5bcec30ae2f33bb0c9e542397 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47be60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47be60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x608, VA 0xffffffff8ac25d68, JMP target 0xffffffff8b5d6020; Evidence ev_dbaaa0cddcf1366587dfd0751616c2dab4323e2dc32d8c16aa4d2b25628e49eb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5d6020); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5d6020(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x610, VA 0xffffffff8ac25d70, JMP target 0xffffffff8b5d6270; Evidence ev_277ff16adb4dc52a98ca821a0016abe3d97fc369633b711460de64205cb9770c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5d6270); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5d6270(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x618, VA 0xffffffff8ac25d78, JMP target 0xffffffff8b5d6720; Evidence ev_2b83cf12957e5aa302449a72d3673745ccad09270241cd71fe4c67ecc19b4c66 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5d6720); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5d6720(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x620, VA 0xffffffff8ac25d80, JMP target 0xffffffff8b5d6880; Evidence ev_2e604388f59c42ac205152ea61568285cc37b25f39feac41209eff26dc3aced1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5d6880); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5d6880(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x628, VA 0xffffffff8ac25d88, JMP target 0xffffffff8b5d63d0; Evidence ev_10812e7ac43e61a7e1e489d15cf584edecbedd23a98f652c74a46907b2e044d4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5d63d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5d63d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x630, VA 0xffffffff8ac25d90, JMP target 0xffffffff8b5d64f0; Evidence ev_1eb84d9197a1a9acda04e182a5f8b77cfbfdc37b84a995124ef4203a25686265 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5d64f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5d64f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x638, VA 0xffffffff8ac25d98, JMP target 0xffffffff8b5d65d0; Evidence ev_f7443ba4a511248b835c2c3801d7acb9e15e6e921cda4e347b2fd8bcc1dfed5c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5d65d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5d65d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x640, VA 0xffffffff8ac25da0, JMP target 0xffffffff8b5d6660; Evidence ev_10fdd5c950efa6245dbdca7f834004136c4b2da909e9047b94621cf4bb238952 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5d6660); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5d6660(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x648, VA 0xffffffff8ac25da8, JMP target 0xffffffff8b487240; Evidence ev_c86f73c6dfa1328f588652c15059dfe12c5b81176a9799dc98d7c0a489f50dee */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b487240); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b487240(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x650, VA 0xffffffff8ac25db0, JMP target 0xffffffff8b4873c0; Evidence ev_8085d868dd8fd6588922db17dc6939f2262cfa3ec4e4a7ebc72d0b629ffae6a6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4873c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4873c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x658, VA 0xffffffff8ac25db8, JMP target 0xffffffff8b47c510; Evidence ev_c031c3ac004c67fdaab4c1c71b598ed974efa473289a8f7a2674f36f3e9f3b97 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47c510); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47c510(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x660, VA 0xffffffff8ac25dc0, JMP target 0xffffffff8aeb5e60; Evidence ev_bab936e589d81c09a3d5c6176a4b7671059ccabf73644a260258fb1e92e6d709 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeb5e60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeb5e60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x668, VA 0xffffffff8ac25dc8, JMP target 0xffffffff8afc2fe0; Evidence ev_b35c80762405011f4c016cc97c05e62cec6b7b2b3234b204176f33175e88077a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afc2fe0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afc2fe0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x670, VA 0xffffffff8ac25dd0, JMP target 0xffffffff8afc3260; Evidence ev_c8b0d0b32f652bc20bb75f2e90bc6f346fa0287abe843eea8c7c7d72bd02925b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afc3260); register/stack arguments unchanged. */

undefined8 sub_603260(long param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  long lVar3;
  long *plVar4;
  undefined8 uVar5;
  
  iVar2 = *param_2;
  if (iVar2 - 1U < 99999) {
    iVar1 = func_0xffffffff8ac2d0a8(*(undefined8 *)(param_1 + 0x140));
    if (iVar1 == 0) {
      return 3;
    }
    lVar3 = func_0xffffffff8aefc170(iVar2);
    if (lVar3 == 0) {
      return 3;
    }
    iVar2 = func_0xffffffff8afc9890(*(undefined8 *)(*(long *)(lVar3 + 0x10) + 0x140));
    if (iVar2 == 0) {
      uVar5 = 1;
      goto LAB_ffffffff8afc3492;
    }
  }
  else {
    lVar3 = *(long *)(param_1 + 8);
    if (iVar2 != 0) {
      plVar4 = (long *)func_0xffffffff8b552420(iVar2,*(undefined4 *)(lVar3 + 0xbc));
      if (plVar4 == (long *)0x0) {
        return 3;
      }
      uVar5 = 0;
      func_0xffffffff8ae878b0(plVar4,0,0xffffffff8bc6b551,0x1ac);
      if ((int)plVar4[0x70] == 0) {
        uVar5 = 0;
        func_0xffffffff8ae87520(*plVar4 + 0x18,0,0,0);
      }
      else {
        *(ulong *)(plVar4[0x7f] + 0x160) = *(ulong *)(plVar4[0x7f] + 0x160) & 0xffffffffffbfffff;
        *(ulong *)(plVar4[0x7f] + 0x168) = *(ulong *)(plVar4[0x7f] + 0x168) & 0xffffffffffbfffff;
        *(ulong *)(plVar4[0x7f] + 0x170) = *(ulong *)(plVar4[0x7f] + 0x170) & 0xffffffffffbfffff;
        *(ulong *)(plVar4[0x7f] + 0x178) = *(ulong *)(plVar4[0x7f] + 0x178) & 0xffffffffffbfffff;
        *(ulong *)(plVar4[0x7f] + 0x180) = *(ulong *)(plVar4[0x7f] + 0x180) & 0xffffffffffbfffff;
        *(ulong *)(plVar4[0x7f] + 0x188) = *(ulong *)(plVar4[0x7f] + 0x188) & 0xffffffffffbfffff;
        *(undefined4 *)(plVar4 + 0x70) = 0;
        func_0xffffffff8afc2de0(plVar4);
      }
      goto LAB_ffffffff8afc3492;
    }
    func_0xffffffff8ae86a00(lVar3 + 0x148,0,0,0);
  }
  for (plVar4 = *(long **)(lVar3 + 0x10); plVar4 != (long *)0x0; plVar4 = (long *)plVar4[2]) {
    func_0xffffffff8ae878b0(plVar4,0,0xffffffff8bc6b551,0x1c2);
    if ((int)plVar4[0x70] == 0) {
      func_0xffffffff8ae87520(*plVar4 + 0x18,0,0,0);
    }
    else {
      *(ulong *)(plVar4[0x7f] + 0x160) = *(ulong *)(plVar4[0x7f] + 0x160) & 0xffffffffffbfffff;
      *(ulong *)(plVar4[0x7f] + 0x168) = *(ulong *)(plVar4[0x7f] + 0x168) & 0xffffffffffbfffff;
      *(ulong *)(plVar4[0x7f] + 0x170) = *(ulong *)(plVar4[0x7f] + 0x170) & 0xffffffffffbfffff;
      *(ulong *)(plVar4[0x7f] + 0x178) = *(ulong *)(plVar4[0x7f] + 0x178) & 0xffffffffffbfffff;
      *(ulong *)(plVar4[0x7f] + 0x180) = *(ulong *)(plVar4[0x7f] + 0x180) & 0xffffffffffbfffff;
      *(ulong *)(plVar4[0x7f] + 0x188) = *(ulong *)(plVar4[0x7f] + 0x188) & 0xffffffffffbfffff;
      *(undefined4 *)(plVar4 + 0x70) = 0;
      func_0xffffffff8afc2de0(plVar4);
    }
  }
  uVar5 = 0;
LAB_ffffffff8afc3492:
  func_0xffffffff8ae86fa0(lVar3 + 0x148,0,0,0);
  return uVar5;
}



/* Input +0x678, VA 0xffffffff8ac25dd8, JMP target 0xffffffff8afc34e0; Evidence ev_e87d34241bf12519597cd716b3051cb77957cee95eed3818b59a416d21550f7d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afc34e0); register/stack arguments unchanged. */

undefined8 sub_6034e0(long param_1,int *param_2)

{
  long lVar1;
  int iVar2;
  int iVar3;
  long *plVar4;
  ulong uVar5;
  ulong uVar6;
  undefined8 uVar7;
  long lStack_38;
  
  uVar5 = (ulong)(uint)param_2[2];
  uVar6 = *(ulong *)(param_2 + 4);
  if ((uVar6 & 0xfffffff0007b0000) != 0 || 5 < uVar5) {
    return 0x16;
  }
  iVar3 = *param_2;
  if (((uVar6 & 0xf000000ff) == 0x100000070) || ((uVar6 & 0xf000000ff) == 0x6e)) {
    uVar6 = uVar6 & 0xfff8400ff;
  }
  if (iVar3 - 1U < 99999) {
    iVar2 = func_0xffffffff8ac2d0a8(*(undefined8 *)(param_1 + 0x140));
    if (iVar2 == 0) {
      return 3;
    }
    lStack_38 = func_0xffffffff8aefc170(iVar3);
    if (lStack_38 == 0) {
      return 3;
    }
    iVar3 = func_0xffffffff8afc9890(*(undefined8 *)(*(long *)(lStack_38 + 0x10) + 0x140));
    if (iVar3 == 0) {
      uVar7 = 1;
      goto LAB_ffffffff8afc36e3;
    }
LAB_ffffffff8afc362c:
    plVar4 = *(long **)(lStack_38 + 0x10);
    if (plVar4 == (long *)0x0) {
      uVar7 = 0;
      goto LAB_ffffffff8afc36e3;
    }
    do {
      lVar1 = plVar4[0x7f];
      func_0xffffffff8ae878b0(plVar4,0,0xffffffff8bc6b551,0x219);
      if ((int)plVar4[0x70] == 1) {
        *(ulong *)(lVar1 + 0x160 + uVar5 * 8) = uVar6 | 0x410000;
        func_0xffffffff8afc2d40(plVar4);
      }
      else {
        *(ulong *)(lVar1 + 0x160 + uVar5 * 8) = uVar6 | 0x10000;
        func_0xffffffff8ae87520(*plVar4 + 0x18,0,0,0);
      }
      plVar4 = (long *)plVar4[2];
    } while (plVar4 != (long *)0x0);
  }
  else {
    lStack_38 = *(long *)(param_1 + 8);
    if (iVar3 == 0) {
      func_0xffffffff8ae86a00(lStack_38 + 0x148,0,0,0);
      goto LAB_ffffffff8afc362c;
    }
    plVar4 = (long *)func_0xffffffff8b552420(iVar3,*(undefined4 *)(lStack_38 + 0xbc));
    if (plVar4 == (long *)0x0) {
      return 3;
    }
    lVar1 = plVar4[0x7f];
    func_0xffffffff8ae878b0(plVar4,0,0xffffffff8bc6b551,0x207);
    if ((int)plVar4[0x70] == 1) {
      *(ulong *)(lVar1 + 0x160 + uVar5 * 8) = uVar6 | 0x410000;
      func_0xffffffff8afc2d40(plVar4);
    }
    else {
      *(ulong *)(lVar1 + 0x160 + uVar5 * 8) = uVar6 | 0x10000;
      func_0xffffffff8ae87520(*plVar4 + 0x18,0,0,0);
    }
  }
  uVar7 = 0;
LAB_ffffffff8afc36e3:
  func_0xffffffff8ae86fa0(lStack_38 + 0x148,0,0,0);
  return uVar7;
}



/* Input +0x680, VA 0xffffffff8ac25de0, JMP target 0xffffffff8afc3710; Evidence ev_cf8cbcf95eb7d439df58bcf90f4bdfb4d5a032b27f8a62eb49952bf4d47ad962 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afc3710); register/stack arguments unchanged. */

undefined8 sub_603710(long param_1,int *param_2)

{
  uint uVar1;
  long lVar2;
  int iVar3;
  int iVar4;
  long lVar5;
  long *plVar6;
  undefined8 uVar7;
  
  uVar1 = param_2[2];
  if (uVar1 - 6 < 0xfffffff9) {
    return 0x16;
  }
  iVar4 = *param_2;
  uVar7 = *(undefined8 *)(param_2 + 4);
  if (iVar4 - 1U < 99999) {
    iVar3 = func_0xffffffff8ac2d0a8(*(undefined8 *)(param_1 + 0x140));
    if (iVar3 == 0) {
      return 3;
    }
    lVar5 = func_0xffffffff8aefc170(iVar4);
    if (lVar5 == 0) {
      return 3;
    }
    iVar4 = func_0xffffffff8afc9890(*(undefined8 *)(*(long *)(lVar5 + 0x10) + 0x140));
    if (iVar4 == 0) {
      uVar7 = 1;
      goto LAB_ffffffff8afc399f;
    }
  }
  else {
    lVar5 = *(long *)(param_1 + 8);
    if (iVar4 != 0) {
      plVar6 = (long *)func_0xffffffff8b552420(iVar4,*(undefined4 *)(lVar5 + 0xbc));
      if (plVar6 == (long *)0x0) {
        return 3;
      }
      lVar2 = plVar6[0x7f];
      func_0xffffffff8ae878b0(plVar6,0,0xffffffff8bc6b551,0x254);
      if (uVar1 == 0xffffffff) {
        *(undefined8 *)(plVar6[0x7f] + 400) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x198) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1a0) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1a8) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1b0) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1b8) = uVar7;
        iVar4 = (int)plVar6[0x70];
      }
      else {
        *(undefined8 *)(lVar2 + 400 + (ulong)uVar1 * 8) = uVar7;
        iVar4 = (int)plVar6[0x70];
      }
      if (iVar4 == 1) {
        func_0xffffffff8afc2e80(plVar6);
        uVar7 = 0;
      }
      else {
        uVar7 = 0;
        func_0xffffffff8ae87520(*plVar6 + 0x18,0,0,0);
      }
      goto LAB_ffffffff8afc399f;
    }
    func_0xffffffff8ae86a00(lVar5 + 0x148,0,0,0);
  }
  plVar6 = *(long **)(lVar5 + 0x10);
  if (plVar6 == (long *)0x0) {
    uVar7 = 0;
  }
  else {
    do {
      lVar2 = plVar6[0x7f];
      func_0xffffffff8ae878b0(plVar6,0,0xffffffff8bc6b551,0x26d);
      if (uVar1 == 0xffffffff) {
        *(undefined8 *)(plVar6[0x7f] + 400) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x198) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1a0) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1a8) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1b0) = uVar7;
        *(undefined8 *)(plVar6[0x7f] + 0x1b8) = uVar7;
        if ((int)plVar6[0x70] != 1) goto LAB_ffffffff8afc38f2;
LAB_ffffffff8afc3840:
        func_0xffffffff8afc2e80(plVar6);
      }
      else {
        *(undefined8 *)(lVar2 + 400 + (ulong)uVar1 * 8) = uVar7;
        if ((int)plVar6[0x70] == 1) goto LAB_ffffffff8afc3840;
LAB_ffffffff8afc38f2:
        func_0xffffffff8ae87520(*plVar6 + 0x18,0,0,0);
      }
      plVar6 = (long *)plVar6[2];
    } while (plVar6 != (long *)0x0);
    uVar7 = 0;
  }
LAB_ffffffff8afc399f:
  func_0xffffffff8ae86fa0(lVar5 + 0x148,0,0,0);
  return uVar7;
}



/* Input +0x688, VA 0xffffffff8ac25de8, JMP target 0xffffffff8afc39d0; Evidence ev_3d00eaece90f35be4dda0c64eddeabc07f8055b40d54c2618adb3f748ce3cfae */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afc39d0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_6039d0(long param_1,undefined4 *param_2)

{
  byte bVar1;
  uint uVar2;
  long lVar3;
  long lVar4;
  code *pcVar5;
  undefined8 uVar6;
  long *plVar7;
  long lVar8;
  long *in_GS_OFFSET;
  undefined8 uStack_40;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  uVar6 = 0x16;
  uVar2 = param_2[2];
  if (5 < (ulong)uVar2) goto LAB_ffffffff8afc3c21;
  lVar3 = *(long *)(param_1 + 8);
  plVar7 = (long *)func_0xffffffff8b552420(*param_2,*(undefined4 *)(lVar3 + 0xbc));
  if (plVar7 == (long *)0x0) {
    uVar6 = 3;
    goto LAB_ffffffff8afc3c21;
  }
  lVar4 = plVar7[0x7f];
  func_0xffffffff8ae878b0(plVar7,0,0xffffffff8bc6b551,0x297);
  if ((int)plVar7[0x70] == 1) {
    if ((int)plVar7[0x80] == 4) {
      if (plVar7 == (long *)*in_GS_OFFSET) {
        uVar6 = rdmsr(0xc0010201);
        *(undefined8 *)(plVar7[0x7f] + 400) = uVar6;
        uVar6 = rdmsr(0xc0010203);
        *(undefined8 *)(plVar7[0x7f] + 0x198) = uVar6;
        uVar6 = rdmsr(0xc0010205);
        *(undefined8 *)(plVar7[0x7f] + 0x1a0) = uVar6;
        uVar6 = rdmsr(0xc0010207);
        *(undefined8 *)(plVar7[0x7f] + 0x1a8) = uVar6;
        uVar6 = rdmsr(0xc0010209);
        *(undefined8 *)(plVar7[0x7f] + 0x1b0) = uVar6;
        uVar6 = rdmsr(0xc001020b);
        *(undefined8 *)(plVar7[0x7f] + 0x1b8) = uVar6;
        goto LAB_ffffffff8afc3b96;
      }
      *(undefined4 *)(plVar7 + 0x70) = 5;
      func_0xffffffff8ae87520(*plVar7 + 0x18,0,0,0);
      func_0xffffffff8ae87190(0xffffffff8e6ce908,0,0,0);
      func_0xffffffff8b1de4d0(*(undefined4 *)((long)plVar7 + 0x524),7);
      bVar1 = *(byte *)(plVar7 + 0x70);
      while ((bVar1 & 6) != 0) {
        bVar1 = *(byte *)(plVar7 + 0x70);
      }
      lVar8 = -0x719316f8;
    }
    else {
LAB_ffffffff8afc3b96:
      lVar8 = *plVar7 + 0x18;
    }
    func_0xffffffff8ae87520(lVar8,0,0,0);
    func_0xffffffff8ae878b0(plVar7,0,0xffffffff8bc6b551,0x29b);
  }
  uStack_40 = *(undefined8 *)(lVar4 + 400 + (ulong)uVar2 * 8);
  func_0xffffffff8ae87520(*plVar7 + 0x18,0,0,0);
  func_0xffffffff8ae86fa0(lVar3 + 0x148,0,0,0);
  uVar6 = *(undefined8 *)(param_2 + 4);
  func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
  uVar6 = func_0xffffffff8ac191d0(&uStack_40,uVar6,8);
LAB_ffffffff8afc3c21:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar5 = (code *)invalidInstructionException();
    (*pcVar5)();
  }
  return uVar6;
}



/* Input +0x690, VA 0xffffffff8ac25df0, JMP target 0xffffffff8b47ac50; Evidence ev_811da2e1050617bf434536219c23c1f0b8e7b8ca55ae11a9fbbc437f7f6016e8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47ac50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47ac50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x698, VA 0xffffffff8ac25df8, JMP target 0xffffffff8b2bc610; Evidence ev_bfce069ca6324f15e1600ceb7a1d3ef4b9c58ba1864c4b3b07433b8b7c8df6d2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bc610); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bc610(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6a0, VA 0xffffffff8ac25e00, JMP target 0xffffffff8aea1a70; Evidence ev_8f85ead00427c91c3ac80e88709da994695cf11f28a33c2de389e5aa84a12cb4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aea1a70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aea1a70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6a8, VA 0xffffffff8ac25e08, JMP target 0xffffffff8b47c5f0; Evidence ev_a581025bc44da8c813edfe81b135518d3b1aed8c9a11442578efc402c841716b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47c5f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47c5f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6b0, VA 0xffffffff8ac25e10, JMP target 0xffffffff8b3f67e0; Evidence ev_ad2def86891f2483c156b143f25a68392b1d3ebb26e355e253a88f3780ffe14b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f67e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3f67e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6b8, VA 0xffffffff8ac25e18, JMP target 0xffffffff8b660630; Evidence ev_0934b36156856e7950bec89b4de073e9eb66aae7bbae345ee9897c25d0ae2724 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b660630); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b660630(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6c0, VA 0xffffffff8ac25e20, JMP target 0xffffffff8b3f68e0; Evidence ev_f8b064b782c277183297729f2ef4a732009499dbc5d89a1a8f522508f0ec93a9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f68e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3f68e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6c8, VA 0xffffffff8ac25e28, JMP target 0xffffffff8b0eecc0; Evidence ev_8c89196783af72e35b2f595b1879fc12b733c3b351ac495574decc52887abe99 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0eecc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0eecc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6d0, VA 0xffffffff8ac25e30, JMP target 0xffffffff8aeb7370; Evidence ev_bfc93836b790f69e71ef7a48f266381779cb2ed20859a290d7822602dc14be98 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeb7370); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeb7370(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6d8, VA 0xffffffff8ac25e38, JMP target 0xffffffff8b3f6b00; Evidence ev_9e18b6a1701c74d053dda57283e3453d8c3c6a21d8227b080a85c1c97d5f81f6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f6b00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3f6b00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6e0, VA 0xffffffff8ac25e40, JMP target 0xffffffff8b3f6b90; Evidence ev_86f25506f96640da0b6f04b953c197a1d6a0e8e20b5b07c30a9459e96ff24f9f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f6b90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3f6b90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6e8, VA 0xffffffff8ac25e48, JMP target 0xffffffff8b47c710; Evidence ev_2cca0e7ec14c945cfe34d45c50710880b41f8a937f3b4197af69e7b5245991da */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47c710); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47c710(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6f0, VA 0xffffffff8ac25e50, JMP target 0xffffffff8af67f60; Evidence ev_00b1250925dbebebc05b066d082f31470c6863b93927939705a4316b3b7c6dd4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af67f60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af67f60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x6f8, VA 0xffffffff8ac25e58, JMP target 0xffffffff8b3f6bc0; Evidence ev_ed64f8cf1ce71d162e665345e6a893536c27457fcd21957b3a02684135c19dad */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f6bc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3f6bc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x700, VA 0xffffffff8ac25e60, JMP target 0xffffffff8b47ca10; Evidence ev_714e17f0ce9e7da1734682518764a2bb1ac07aeaf66f4439c9e22d0dd94f0231 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47ca10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47ca10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x708, VA 0xffffffff8ac25e68, JMP target 0xffffffff8b47cc00; Evidence ev_8fe2e23e9abba8505fd36d50d41316949211ae18a20cdeee929159529d13020a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47cc00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47cc00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x710, VA 0xffffffff8ac25e70, JMP target 0xffffffff8adf8c90; Evidence ev_f6f0337a1c2bf71d8ae8329cca392e3670310f0b3fc40dc7acb21b11b953b13b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf8c90); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_entry_616(long param_1,undefined4 *param_2)

{
  code *pcVar1;
  int iVar2;
  long lVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 *in_GS_OFFSET;
  undefined1 auStack_58 [40];
  long lStack_30;
  
  lStack_30 = _DAT_ffffffff8e2dc310;
  func_0xffffffff8ac18ff0(auStack_58,0x20);
  lVar3 = func_0xffffffff8b552420(*param_2,*(undefined4 *)(*(long *)(param_1 + 8) + 0xbc));
  if (lVar3 == 0) {
    iVar2 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
    uVar4 = 3;
    if (iVar2 == 0) goto LAB_ffffffff8adf8d45;
    lVar3 = func_0xffffffff8b552420(*param_2,0xffffffff);
    if (lVar3 != 0) goto LAB_ffffffff8adf8cdc;
    lVar3 = func_0xffffffff8aefc170(*param_2);
    uVar4 = 3;
    if (lVar3 == 0) goto LAB_ffffffff8adf8d45;
    iVar2 = func_0xffffffff8afc90d0(*(undefined8 *)(param_1 + 0x140));
    if ((iVar2 != 0) && ((*(byte *)(lVar3 + 0xb1) & 2) != 0)) {
      func_0xffffffff8ae86fa0(lVar3 + 0x148,0,0,0);
      uVar4 = 0xd;
      goto LAB_ffffffff8adf8d45;
    }
    func_0xffffffff8b317b70(auStack_58,lVar3 + 0x5e4,0x20);
    func_0xffffffff8ae86fa0(lVar3 + 0x148,0,0,0);
    uVar4 = *(undefined8 *)(param_2 + 2);
    lVar3 = func_0xffffffff8ae04eb0(auStack_58,0x1f);
    uVar5 = *in_GS_OFFSET;
  }
  else {
LAB_ffffffff8adf8cdc:
    func_0xffffffff8b317b70(auStack_58,lVar3 + 0x294,0x20);
    func_0xffffffff8ae86fa0(*(long *)(lVar3 + 8) + 0x148,0,0,0);
    uVar4 = *(undefined8 *)(param_2 + 2);
    lVar3 = func_0xffffffff8ae04eb0(auStack_58,0x1f);
    uVar5 = *in_GS_OFFSET;
  }
  func_0xffffffff8b5da3e0(uVar5,0xffffffff8bd0f297,0);
  uVar4 = func_0xffffffff8ac191d0(auStack_58,uVar4,lVar3 + 1);
LAB_ffffffff8adf8d45:
  if (_DAT_ffffffff8e2dc310 == lStack_30) {
    return uVar4;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0x718, VA 0xffffffff8ac25e78, JMP target 0xffffffff8b292570; Evidence ev_ed559c296ef2c8b95c650f8641a3c5d7febedff4553f1e489f7d393b67900318 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b292570); register/stack arguments unchanged. */

undefined8 handler_body_617(undefined8 param_1,undefined1 *param_2)

{
  int iVar1;
  
  iVar1 = func_0xffffffff8b48ce10();
  if (iVar1 != 0) {
    func_0xffffffff8b0284a0(*param_2);
  }
  return 0;
}



/* Input +0x720, VA 0xffffffff8ac25e80, JMP target 0xffffffff8b47d0f0; Evidence ev_990c00e3de2b0843e70550c3a2b0f22ce34f201ab751d4d1882443420a3bf4ca */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47d0f0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong handler_body_618(long param_1,undefined8 *param_2)

{
  long *plVar1;
  long lVar2;
  code *pcVar3;
  int iVar4;
  uint uVar5;
  long lVar6;
  undefined8 uVar7;
  ulong uVar8;
  undefined8 uStack_78;
  long lStack_70;
  undefined8 *puStack_68;
  undefined4 uStack_60;
  undefined8 uStack_58;
  long lStack_50;
  undefined8 uStack_48;
  long lStack_40;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  iVar4 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar4 == 0) {
    uVar8 = 1;
LAB_ffffffff8b47d405:
    if (_DAT_ffffffff8e2dc310 == lStack_38) {
      return uVar8;
    }
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  uStack_78 = *param_2;
  puStack_68 = &uStack_78;
  lStack_70 = (long)*(int *)(param_2 + 1);
  uStack_60 = 1;
  uStack_58 = 0;
  uStack_48 = 0;
  lStack_50 = lStack_70;
  lStack_40 = param_1;
LAB_ffffffff8b47d17e:
  func_0xffffffff8ae86a00(0xffffffff8dede060,0,0,0);
  iVar4 = 0;
  if (_DAT_ffffffff8dede038 != 0) {
    iVar4 = 0;
    lVar6 = _DAT_ffffffff8dede038;
    do {
      lVar6 = *(long *)(lVar6 + 0x20);
      iVar4 = iVar4 + 1;
    } while (lVar6 != 0);
  }
  func_0xffffffff8ae86fa0(0xffffffff8dede060,0,0,0);
  uVar7 = func_0xffffffff8b5c8b50((long)iVar4 * 0x128,0xffffffff8d5bc080,0x102);
  func_0xffffffff8ae86a00(0xffffffff8dede060,0,0,0);
  lVar6 = _DAT_ffffffff8dede038;
  if (_DAT_ffffffff8dede038 != 0) {
    do {
      lVar2 = lVar6 + 0x18;
      func_0xffffffff8b1946a0(lVar2,0,0);
      if ((*(uint *)(lVar6 + 0xa0) & 8) == 0) {
        if (iVar4 < 1) goto LAB_ffffffff8b47d340;
        if ((ulong)*(byte *)(lVar6 + 0x9d) < 9) {
                    /* WARNING: Could not emulate address calculation at 0xffffffff8b47d2c3 */
                    /* WARNING: Treating indirect jump as call */
          uVar8 = (*(code *)((long)*(int *)((ulong)*(byte *)(lVar6 + 0x9d) * 4 + -0x73d64098) +
                            -0x73d64098))();
          return uVar8;
        }
      }
      func_0xffffffff8b194eb0(lVar2,0,0);
      plVar1 = (long *)(lVar6 + 0x20);
      lVar6 = *plVar1;
      if (*plVar1 == 0) break;
    } while( true );
  }
  func_0xffffffff8ae86fa0(0xffffffff8dede060,0,0,0);
  uVar5 = func_0xffffffff8b142520(uVar7,0,&puStack_68);
  uVar8 = (ulong)uVar5;
  func_0xffffffff8b5c8df0(uVar7,0xffffffff8d5bc080);
  if (uVar5 == 0) {
    uVar8 = 0;
    if (param_2[2] != 0) {
      iVar4 = func_0xffffffff8ac19720(param_2[2],0);
      uVar8 = 0xe;
      if (iVar4 == 0) {
        uVar8 = 0;
      }
    }
  }
  goto LAB_ffffffff8b47d405;
LAB_ffffffff8b47d340:
  func_0xffffffff8b194eb0(lVar2,0,0);
  func_0xffffffff8ae86fa0(0xffffffff8dede060,0,0);
  func_0xffffffff8b5c8df0(uVar7);
  goto LAB_ffffffff8b47d17e;
}



/* Input +0x728, VA 0xffffffff8ac25e88, JMP target 0xffffffff8b3f7650; Evidence ev_ec79fc00d933f0fa3adc6c589beb6ef0761e1abf6982520b1e73fd065185a03b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f7650); register/stack arguments unchanged. */

undefined8 handler_body_619(void)

{
  return 0x4e;
}



/* Input +0x730, VA 0xffffffff8ac25e90, JMP target 0xffffffff8b47d430; Evidence ev_d8ad9b012bf77afc6e04f0afd8e2bac55fff3ae89aee1a08ea8d103af0f85cbe */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47d430); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_620(long param_1)

{
  undefined8 uVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  ulong uVar5;
  long lStack_30;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  uVar1 = *(undefined8 *)(*(long *)(param_1 + 8) + 0x200);
  uVar5 = *(long *)(*(long *)(param_1 + 0x460) + 0x100) - 0x80U & 0xffffffffffffc000;
  func_0xffffffff8ac86820(uVar1,0,0);
  iVar3 = func_0xffffffff8ac86c40(uVar1,uVar5,&lStack_30);
  if (iVar3 != 0) {
    uVar4 = (uint)(uVar5 - *(long *)(lStack_30 + 0x20) >> 0xe);
    if (0 < (int)uVar4) {
      func_0xffffffff8ae23610
                (*(undefined8 *)(lStack_30 + 0x50),*(long *)(lStack_30 + 0x58) >> 0xe,
                 uVar4 & 0x7fffffff,5);
    }
  }
  func_0xffffffff8ac86870(uVar1,0,0);
  if (_DAT_ffffffff8e2dc310 == lStack_28) {
    return 0;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* Input +0x738, VA 0xffffffff8ac25e98, JMP target 0xffffffff8b19cd40; Evidence ev_1276a5eb49b3987506ea265503404f41aa574a24c242b2b96b29414a2bc07770 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b19cd40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b19cd40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x740, VA 0xffffffff8ac25ea0, JMP target 0xffffffff8b2925a0; Evidence ev_fb10e03c61dd147ccbca31c1b8d93475708b293a86477485e2d532ba24b822e3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2925a0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_623(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 *in_GS_OFFSET;
  undefined4 uStack_24;
  long lStack_20;
  
  lStack_20 = _DAT_ffffffff8e2dc310;
  iVar2 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar2 == 0) {
    uVar3 = 1;
  }
  else {
    uStack_24 = 0;
    iVar2 = func_0xffffffff8b48ce10();
    if (iVar2 != 0) {
      func_0xffffffff8b028540(&uStack_24);
    }
    uVar3 = *param_2;
    func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
    uVar3 = func_0xffffffff8ac191d0(&uStack_24,uVar3,4);
  }
  if (_DAT_ffffffff8e2dc310 == lStack_20) {
    return uVar3;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0x748, VA 0xffffffff8ac25ea8, JMP target 0xffffffff8b47d4f0; Evidence ev_f66ec0a8ccd0a0f4e2d2cf9c673c9bcced56c54622dca4ee88355d73870537ba */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47d4f0); register/stack arguments unchanged. */

undefined8 handler_body_624(long param_1)

{
  long lVar1;
  
  lVar1 = *(long *)(*(long *)(param_1 + 8) + 0x200);
  func_0xffffffff8ac86820(lVar1,0,0);
  *(ulong *)(param_1 + 0x408) = (ulong)*(uint *)(lVar1 + 0x1c4);
  func_0xffffffff8ac86870(lVar1,0,0);
  return 0;
}



/* Input +0x750, VA 0xffffffff8ac25eb0, JMP target 0xffffffff8afc3c90; Evidence ev_5449672449fb2bd3220062da2a37fdba25e6481f178467f8a8db238fcc501e64 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afc3c90); register/stack arguments unchanged. */

undefined8 handler_body_625(undefined8 param_1,int *param_2)

{
  undefined8 uVar1;
  
  if (*param_2 - 1U < 0x17) {
                    /* WARNING: Could not emulate address calculation at 0xffffffff8afc3cbe */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (*(code *)((long)*(int *)((ulong)(*param_2 - 1U) * 4 + -0x73f1caa0) + -0x73f1caa0))();
    return uVar1;
  }
  return 0x16;
}



/* Input +0x758, VA 0xffffffff8ac25eb8, JMP target 0xffffffff8afc4cf0; Evidence ev_3e0f5663d5b05fdf65bd4dcf09c06052191f67028cf23118d18971699d1f689e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afc4cf0); register/stack arguments unchanged. */

/* WARNING: Removing unreachable block (ram,0xffffffff8afc4fee) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_626(undefined8 param_1,int *param_2)

{
  undefined8 uVar1;
  
  if (5 < *param_2 - 1U) {
    return 0x16;
  }
                    /* WARNING: Could not emulate address calculation at 0xffffffff8afc4e66 */
                    /* WARNING: Treating indirect jump as call */
  uVar1 = (*(code *)((long)*(int *)((ulong)(*param_2 - 1U) * 4 + -0x73f1ca44) + -0x73f1ca44))();
  return uVar1;
}



/* Input +0x760, VA 0xffffffff8ac25ec0, JMP target 0xffffffff8ae62850; Evidence ev_e1b4c3263b3691353fa67c2117ee45beccbaddec70b000f5bfd63b251c314cdc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae62850); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int handler_body_627(long param_1,long *param_2)

{
  long *plVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  long lVar6;
  long lVar7;
  ulong uVar8;
  long *plVar9;
  long *plVar10;
  long *plVar11;
  long lStack_108;
  long lStack_100;
  long lStack_f8;
  long lStack_f0;
  long lStack_78;
  ulong uStack_70;
  long *plStack_68;
  undefined4 uStack_60;
  undefined8 uStack_58;
  ulong uStack_50;
  undefined8 uStack_48;
  long lStack_40;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  iVar3 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar3 == 0) {
    iVar3 = 0x4e;
  }
  else {
    sub_4a2ce0();
    if (*param_2 == 0) {
      iVar3 = 0;
      func_0xffffffff8b60b350(0xffffffff8df49e60,0,0,0);
      if (_DAT_ffffffff8df49e80 != (long *)0x0) {
        iVar3 = 0;
        plVar10 = _DAT_ffffffff8df49e80;
        do {
          func_0xffffffff8ae86a00(plVar10 + 0x29,0,0,0);
          iVar3 = iVar3 + (int)plVar10[0x169];
          func_0xffffffff8ae86fa0(plVar10 + 0x29,0,0);
          plVar10 = (long *)*plVar10;
        } while (plVar10 != (long *)0x0);
      }
      func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
      iVar5 = func_0xffffffff8ac19790(param_2[1],iVar3);
      iVar3 = 0xe;
      if (iVar5 == 0) {
        iVar3 = 0;
      }
    }
    else {
      uVar4 = func_0xffffffff8b142a40(param_2[1]);
      if (uVar4 == 0xffffffff) {
        iVar3 = 0xe;
      }
      else if ((int)uVar4 < 1) {
        iVar3 = 0x16;
      }
      else {
        lStack_78 = *param_2;
        iVar5 = 0;
        uStack_70 = (ulong)uVar4 * 0x28;
        plStack_68 = &lStack_78;
        uStack_60 = 1;
        uStack_58 = 0;
        uStack_48 = 0;
        uStack_50 = uStack_70;
        lStack_40 = param_1;
        func_0xffffffff8b60b350(0xffffffff8df49e60,0,0,0);
        if (_DAT_ffffffff8df49e80 != (long *)0x0) {
          iVar5 = 0;
          plVar10 = _DAT_ffffffff8df49e80;
          do {
            plVar1 = plVar10 + 0x29;
            while (func_0xffffffff8ae86a00(plVar1,0,0,0), (int)plVar10[0x17] == 1) {
              lVar7 = plVar10[0x169];
              func_0xffffffff8ae86fa0(plVar1,0,0);
              uVar8 = (long)(int)lVar7 * 0x28;
              lVar6 = func_0xffffffff8b5c8b50(uVar8,0xffffffff8c488120,0x102);
              func_0xffffffff8ae86a00(plVar1,0,0,0);
              if ((int)plVar10[0x169] <= (int)lVar7) {
                func_0xffffffff8ae87190(plVar10 + 0x2d,0,0);
                plVar11 = (long *)plVar10[2];
                if (plVar11 != (long *)0x0) {
                  plVar9 = (long *)(lVar6 + 0x20);
                  do {
                    func_0xffffffff8ae878b0(plVar11,0,0xffffffff8bc6a1cd,0x647);
                    *(undefined4 *)(plVar9 + -4) = *(undefined4 *)((long)plVar10 + 0xbc);
                    *(undefined4 *)((long)plVar9 + -0x1c) = *(undefined4 *)((long)plVar11 + 0x9c);
                    func_0xffffffff8ae61a20(plVar11);
                    if ((*(byte *)((long)plVar11 + 0xed) & 4) == 0) {
                      plVar9[-2] = lStack_100;
                      plVar9[-3] = lStack_108;
                      *plVar9 = lStack_f0;
                      plVar9[-1] = lStack_f8;
                    }
                    else {
                      plVar9[-3] = 0;
                      plVar9[-2] = 0;
                      lVar7 = func_0xffffffff8b4909c0(plVar11[0x47]);
                      plVar9[-1] = lVar7 / 1000000;
                      *plVar9 = lVar7 % 1000000;
                    }
                    func_0xffffffff8ae87520(*plVar11 + 0x18,0,0);
                    plVar11 = (long *)plVar11[2];
                    plVar9 = plVar9 + 5;
                    iVar5 = iVar5 + 1;
                  } while (plVar11 != (long *)0x0);
                }
                func_0xffffffff8ae87520(plVar10 + 0x2d,0,0);
                func_0xffffffff8ae86fa0(plVar1,0,0);
                if (uStack_50 < uVar8) {
                  uVar8 = uStack_50;
                }
                iVar3 = func_0xffffffff8b142520(lVar6,uVar8 & 0xffffffff,&plStack_68);
                func_0xffffffff8b5c8df0(lVar6);
                if (iVar3 != 0) {
                  func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
                  goto LAB_ffffffff8ae62cb3;
                }
                goto LAB_ffffffff8ae6294e;
              }
              func_0xffffffff8ae86fa0(plVar1,0,0);
              func_0xffffffff8b5c8df0(lVar6);
            }
            func_0xffffffff8ae86fa0(plVar1,0,0);
LAB_ffffffff8ae6294e:
            plVar10 = (long *)*plVar10;
          } while (plVar10 != (long *)0x0);
        }
        func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
        iVar5 = func_0xffffffff8ac19790(param_2[1],iVar5);
        iVar3 = 0xe;
        if (iVar5 == 0) {
          iVar3 = 0;
        }
      }
    }
  }
LAB_ffffffff8ae62cb3:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return iVar3;
}



/* Input +0x768, VA 0xffffffff8ac25ec8, JMP target 0xffffffff8b47d540; Evidence ev_02828c9b04644899c4f8a28759e9839aab1318a8fa28c11bedd0880bf56b6461 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47d540); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 handler_body_628(long param_1,ulong *param_2)

{
  uint uVar1;
  int iVar2;
  ulong uVar3;
  ulong uVar4;
  long lVar5;
  long lVar6;
  code *pcVar7;
  uint uVar8;
  ulong uVar9;
  int iVar10;
  undefined4 uVar11;
  long lVar12;
  ulong uVar13;
  ulong uVar14;
  uint uVar15;
  long *in_GS_OFFSET;
  bool bVar16;
  ulong uStack_40;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  uVar14 = *param_2;
  uVar3 = param_2[1];
  uVar1 = (uint)param_2[4];
  uVar4 = param_2[5];
  iVar2 = (int)param_2[2];
  lVar5 = *in_GS_OFFSET;
  uVar8 = (uint)param_2[3] & 0xff;
  if (0x2ffffff < *(uint *)(*(long *)(lVar5 + 8) + 0x5d4)) {
    uVar8 = (uint)param_2[3];
  }
  uStack_40 = uVar14;
  iVar10 = func_0xffffffff8afc9560(*(undefined8 *)(param_1 + 0x140));
  uVar11 = 1;
  if (iVar10 != 0) goto LAB_ffffffff8b47d60e;
  iVar10 = func_0xffffffff8afc95a0(*(undefined8 *)(lVar5 + 0x140));
  if (iVar10 == 0) {
    iVar10 = func_0xffffffff8afc92d0(*(undefined8 *)(param_1 + 0x140));
    if (iVar10 == 0) {
      uVar11 = 0x16;
      if (((uVar14 & 0x3fff) != 0) || (uVar3 < 0x4000 || (uVar3 & 0x3fff) != 0))
      goto LAB_ffffffff8b47d60e;
      if ((iVar2 == -1) ||
         (iVar10 = func_0xffffffff8ad833e0(iVar2,*(undefined8 *)(param_1 + 8)), iVar10 != 0)) {
        uVar11 = 0x16;
        if ((((uVar8 & 0xfffffc0c) != 0) ||
            (uVar11 = 0x16, (uVar4 & 0x3fff) != 0 || (uVar1 & 0x9fdf2f) != 0)) ||
           (((uVar1 & 0x40) != 0 && ((0x4000 < uVar3 || ((uVar8 & 3) == 0))))))
        goto LAB_ffffffff8b47d60e;
        if (((uVar1 & 0x200000) == 0) ||
           (iVar10 = func_0xffffffff8b4e4300(*(undefined8 *)(lVar5 + 8)), iVar10 != 0)) {
          lVar12 = func_0xffffffff8b478320(param_1);
          uVar13 = lVar12 - 0x7f0000000;
          if (((uVar13 < 0x800000000) || (uVar8 < 0x40)) ||
             (*(char *)(*(long *)(lVar5 + 8) + 0xc81) != '\0')) {
            lVar6 = *(long *)(*(long *)(param_1 + 8) + 0x200);
            if ((uVar1 & 0x10) == 0) {
              if (uVar14 == 0) {
                uVar13 = *(ulong *)((ulong)(uVar13 < 0x800000000) * 0x10 + 0x1f8 + lVar6);
                uVar9 = uVar13;
              }
              else if ((uVar13 < 0x800000000) ||
                      (uVar13 = 0xff0000000, uVar9 = 0xff0000000,
                      0xff0000000 < uVar14 || uVar3 + uVar14 < 0x7f0000000)) {
                uVar13 = uVar14;
                uVar9 = uStack_40;
              }
              uStack_40 = uVar9;
              uVar14 = uVar13;
              if ((uVar1 & 0xff000000) == 0) {
                uVar15 = 1;
                if ((*(byte *)(lVar6 + 0x244) & 2) == 0) {
                  uVar15 = (*(uint *)(*(long *)(param_1 + 8) + 0x5d8) < 0x1500000) + 1;
                }
              }
              else if ((uVar1 & 0xff000000) == 0x1000000) {
                bVar16 = *(char *)(*(long *)(lVar5 + 8) + 0xc81) != '\0';
                uVar15 = bVar16 + 1 + (uint)bVar16;
              }
              else {
                uVar15 = (int)uVar1 >> 0x10 & 0xffffff00;
              }
              uVar11 = *(undefined4 *)(*(long *)(lVar5 + 8) + 0x5c4);
            }
            else {
              if (uVar14 == 0) {
                uVar11 = 0x16;
                goto LAB_ffffffff8b47d60e;
              }
              uVar11 = 0x16;
              if (((CARRY8(uVar14,uVar3) || uVar14 < *(ulong *)(lVar6 + 0x20)) ||
                  (*(ulong *)(lVar6 + 0x28) < uVar14 + uVar3)) ||
                 ((0x7ffffffff < uVar13 && (uVar14 >> 0x1c < 0xff && 0x7efffffff < uVar14 + uVar3)))
                 ) goto LAB_ffffffff8b47d60e;
              uVar11 = *(undefined4 *)(*(long *)(lVar5 + 8) + 0x5c4);
              uVar15 = 0;
            }
            uVar11 = func_0xffffffff8ad8b450
                               (param_1,lVar6,&uStack_40,uVar11,uVar4,uVar14,uVar3,iVar2,
                                uVar8 >> 1 & 0x141 | uVar8,uVar15,uVar1,lVar12,0);
            *(ulong *)(param_1 + 0x408) = uStack_40;
            goto LAB_ffffffff8b47d60e;
          }
        }
      }
      uVar11 = 0x16;
      goto LAB_ffffffff8b47d60e;
    }
    func_0xffffffff8ac1d410(0xffffffff8bd36c18);
  }
  uVar11 = 1;
LAB_ffffffff8b47d60e:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar7 = (code *)invalidInstructionException();
    (*pcVar7)();
  }
  return uVar11;
}



/* Input +0x770, VA 0xffffffff8ac25ed0, JMP target 0xffffffff8b2dc640; Evidence ev_108bce5e9a01a5b532d34dd147050ef2824319b278900df4d687399deb3620c2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2dc640); register/stack arguments unchanged. */

int handler_body_629(long param_1,long *param_2)

{
  long lVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  undefined8 *in_GS_OFFSET;
  
  if (*param_2 == 1) {
    pcVar3 = (char *)0x0;
  }
  else {
    pcVar3 = (char *)func_0xffffffff8b5c8b50(0x400,0xffffffff8cf11e10,2);
    lVar1 = *param_2;
    func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd1a084,0);
    iVar2 = func_0xffffffff8ac19900(lVar1,pcVar3,0x400,0);
    if ((iVar2 != 0) || (iVar2 = 0x16, *pcVar3 != '/')) goto LAB_ffffffff8b2dc71d;
    iVar2 = func_0xffffffff8afc92d0(*(undefined8 *)(param_1 + 0x140));
    if ((iVar2 != 0) && (iVar2 = func_0xffffffff8b291a30(pcVar3,0xffffffff8c1dd494,0xc), iVar2 != 0)
       ) {
      func_0xffffffff8b1cd5a0(0xffffffff8bc64b80,param_1,pcVar3,0xffffffff8c1dd494);
      iVar2 = 2;
      goto LAB_ffffffff8b2dc71d;
    }
  }
  pcVar4 = (char *)0x1;
  if (*param_2 != 1) {
    pcVar4 = pcVar3;
  }
  iVar2 = func_0xffffffff8b2dbca0
                    (param_1,pcVar4,(int)param_2[1],(short)param_2[2],(int)param_2[3],0);
LAB_ffffffff8b2dc71d:
  func_0xffffffff8b5c8df0(pcVar3,0xffffffff8cf11e10);
  return iVar2;
}



/* Input +0x778, VA 0xffffffff8ac25ed8, JMP target 0xffffffff8b2dcc70; Evidence ev_ff3e8df1b182e02220ce0dbd4d2551c4a899fc226b91c1d004b6c1d72a265bff */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2dcc70); register/stack arguments unchanged. */

int sub_91cc70(long param_1,undefined8 *param_2)

{
  undefined8 uVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 *in_GS_OFFSET;
  
  uVar3 = func_0xffffffff8b5c8b50(0x400,0xffffffff8cf11e10,2);
  uVar1 = *param_2;
  func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd1a084,0);
  iVar2 = func_0xffffffff8ac19900(uVar1,uVar3,0x400,0);
  if (iVar2 == 0) {
    iVar2 = func_0xffffffff8afc92d0(*(undefined8 *)(param_1 + 0x140));
    if (iVar2 != 0) {
      iVar2 = func_0xffffffff8b291a30(uVar3,0xffffffff8c1dd4a1,0xc);
      if (iVar2 != 0) {
        func_0xffffffff8b1cd5a0(0xffffffff8bd49e5d,param_1,uVar3,0xffffffff8c1dd4a1);
        iVar2 = 2;
        goto LAB_ffffffff8b2dcd23;
      }
    }
    iVar2 = sub_91c740(param_1,uVar3);
  }
LAB_ffffffff8b2dcd23:
  func_0xffffffff8b5c8df0(uVar3,0xffffffff8cf11e10);
  return iVar2;
}



/* Input +0x780, VA 0xffffffff8ac25ee0, JMP target 0xffffffff8adf8e30; Evidence ev_4cc41713448684d0594ccc69bcaff9fac62572005ddca1bae0ddc764b4812047 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf8e30); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_632(long param_1,long *param_2)

{
  uint uVar1;
  uint uVar2;
  long *plVar3;
  long *plVar4;
  undefined8 uVar5;
  long *plVar6;
  
  if (*param_2 == (long)*(int *)(param_1 + 0x9c)) {
    return 0xb;
  }
  plVar3 = (long *)func_0xffffffff8b552420(*param_2,*(undefined4 *)(*(long *)(param_1 + 8) + 0xbc));
  if (plVar3 == (long *)0x0) {
    return 3;
  }
  func_0xffffffff8ae878b0(plVar3,0,0xffffffff8bcd1b07,0x32f);
  uVar1 = *(uint *)(plVar3 + 0x1d);
  if (((uVar1 & 0x20) == 0) && (uVar2 = *(uint *)((long)plVar3 + 0xe4), -1 < (int)uVar2)) {
    if ((uVar2 & 8) == 0 || (uVar1 & 2) == 0) {
      *(uint *)((long)plVar3 + 0xe4) = uVar2 | 0x80000800;
      if ((int)plVar3[0x80] == 4) {
        func_0xffffffff8b4c35d0(plVar3);
      }
      plVar6 = plVar3 + 1;
      do {
        if ((1 < (int)plVar3[0x80] - 3U) && ((*(byte *)(plVar3 + 0x1d) & 8) == 0))
        goto LAB_ffffffff8adf8fcc;
        func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
        func_0xffffffff8ae86fa0(plVar3[1] + 0x148,0,0,0);
        func_0xffffffff8b5c6830(0xffffffff8bc746cc,_DAT_ffffffff8e2e03d0,0,0x100);
        plVar4 = (long *)func_0xffffffff8b552420((int)*param_2);
        if (plVar4 == (long *)0x0) {
          return 3;
        }
        if (plVar3 != plVar4) {
          plVar6 = plVar4 + 1;
          uVar5 = 3;
          goto LAB_ffffffff8adf9000;
        }
        func_0xffffffff8ae878b0(plVar3,0,0xffffffff8bcd1b07);
      } while (((*(uint *)(plVar3 + 0x1d) & 2) == 0) || ((*(uint *)((long)plVar3 + 0xe4) & 8) == 0))
      ;
      *(uint *)((long)plVar3 + 0xe4) = *(uint *)((long)plVar3 + 0xe4) & 0x7ffff7ff;
      *(undefined4 *)(plVar3 + 0x80) = 1;
      *(uint *)(plVar3 + 0x1d) = *(uint *)(plVar3 + 0x1d) | 0x20;
LAB_ffffffff8adf8fcc:
      uVar5 = 0;
      func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
      goto LAB_ffffffff8adf9000;
    }
    *(undefined4 *)(plVar3 + 0x80) = 1;
    uVar5 = 0;
    *(uint *)(plVar3 + 0x1d) = uVar1 | 0x20;
    func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
  }
  else {
    func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
    uVar5 = 0x16;
  }
  plVar6 = plVar3 + 1;
LAB_ffffffff8adf9000:
  func_0xffffffff8ae86fa0(*plVar6 + 0x148,0,0,0);
  return uVar5;
}



/* Input +0x788, VA 0xffffffff8ac25ee8, JMP target 0xffffffff8adf9070; Evidence ev_cbdcc90163d396e144346a142163cc19e542ef9cc78d2d9f36deaf25b6ca921b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf9070); register/stack arguments unchanged. */

undefined4 handler_body_633(long param_1,long *param_2)

{
  undefined4 uVar1;
  uint uVar2;
  long *plVar3;
  
  if (*param_2 == (long)*(int *)(param_1 + 0x9c)) {
    return 0x16;
  }
  plVar3 = (long *)func_0xffffffff8b552420(*param_2,*(undefined4 *)(*(long *)(param_1 + 8) + 0xbc));
  if (plVar3 == (long *)0x0) {
    return 3;
  }
  func_0xffffffff8ae878b0(plVar3,0,0xffffffff8bcd1b07,0x36c);
  uVar2 = *(uint *)((long)plVar3 + 0xe4);
  if ((*(uint *)(plVar3 + 0x1d) & 0x20) == 0) {
    uVar1 = 0x16;
    if (-1 < (int)uVar2) goto LAB_ffffffff8adf9112;
LAB_ffffffff8adf9104:
    *(uint *)((long)plVar3 + 0xe4) = uVar2 & 0x7fffffff;
  }
  else {
    if ((int)uVar2 < 0) goto LAB_ffffffff8adf9104;
    uVar2 = *(uint *)(plVar3 + 0x1d) & 0xffffffdf;
    *(uint *)(plVar3 + 0x1d) = uVar2;
    if (uVar2 == 0) {
      *(undefined4 *)(plVar3 + 0x80) = 2;
    }
    func_0xffffffff8b5c6b20(plVar3);
  }
  uVar1 = 0;
LAB_ffffffff8adf9112:
  func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
  func_0xffffffff8ae86fa0(plVar3[1] + 0x148,0,0,0);
  return uVar1;
}



/* Input +0x790, VA 0xffffffff8ac25ef0, JMP target 0xffffffff8adf9150; Evidence ev_d01f48c6d3de85ee2d44311c9e2d6926853483ea9fbcadc5af2ea28add6da6fa */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf9150); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_634(long param_1,undefined4 *param_2)

{
  int iVar1;
  code *pcVar2;
  long *plVar3;
  undefined8 uVar4;
  undefined8 *in_GS_OFFSET;
  undefined1 auStack_538 [64];
  undefined1 auStack_4f8 [1216];
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  plVar3 = (long *)func_0xffffffff8b552420(*param_2,*(undefined4 *)(*(long *)(param_1 + 8) + 0xbc));
  uVar4 = 3;
  if (plVar3 != (long *)0x0) {
    do {
      func_0xffffffff8ae878b0(plVar3,0,0xffffffff8bcd1b07,0x390);
      if ((((*(byte *)(param_1 + 0x529) & 1) == 0) && ((*(byte *)(plVar3 + 0x1d) & 0x20) == 0)) &&
         (-1 < *(int *)((long)plVar3 + 0xe4))) {
        func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
        func_0xffffffff8ae86fa0(plVar3[1] + 0x148,0,0,0);
        uVar4 = 0x16;
        goto LAB_ffffffff8adf9341;
      }
      iVar1 = (int)plVar3[0x80];
      if (2 < iVar1 - 2U) {
        if (iVar1 == 1) {
          func_0xffffffff8ac18ff0(auStack_538,0x500);
          func_0xffffffff8b3cbb60(plVar3,auStack_4f8,0);
          func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
          func_0xffffffff8ae86fa0(plVar3[1] + 0x148,0,0,0);
          uVar4 = *(undefined8 *)(param_2 + 2);
          func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
          uVar4 = func_0xffffffff8ac191d0(auStack_538,uVar4,0x4c0);
          goto LAB_ffffffff8adf9341;
        }
        if (iVar1 != 0) {
          func_0xffffffff8b1b1950();
          func_0xffffffff8b1b18a0(0xffffffff8adf935c,(int)plVar3[0x80]);
          func_0xffffffff8b65aa10(3,0xffffffff8bcc726f,(int)plVar3[0x80]);
                    /* WARNING: Does not return */
          pcVar2 = (code *)invalidInstructionException();
          (*pcVar2)();
        }
        func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
        func_0xffffffff8ae86fa0(plVar3[1] + 0x148,0,0,0);
        break;
      }
      func_0xffffffff8ae87520(*plVar3 + 0x18,0,0,0);
      func_0xffffffff8ae86fa0(plVar3[1] + 0x148,0,0,0);
      func_0xffffffff8b5c6830(0xffffffff8bc746cc,_DAT_ffffffff8e2e03d0,0,0x100);
      plVar3 = (long *)func_0xffffffff8b552420(*param_2);
    } while (plVar3 != (long *)0x0);
    uVar4 = 3;
  }
LAB_ffffffff8adf9341:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return uVar4;
}



/* Input +0x798, VA 0xffffffff8ac25ef8, JMP target 0xffffffff8adf93a0; Evidence ev_b1d1f110ab704ed8a66910e3337c8018c772cb489e2603f95289d19d322ec929 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf93a0); register/stack arguments unchanged. */

undefined8 handler_body_635(void)

{
  return 0x4e;
}



/* Input +0x7a0, VA 0xffffffff8ac25f00, JMP target 0xffffffff8b07e4d0; Evidence ev_0192932dffa26a12ca79e92367a118daa0294defe98cb7daa2896b09b64f8b05 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07e4d0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int handler_body_636(long param_1,undefined8 *param_2)

{
  uint uVar1;
  undefined8 uVar2;
  int iVar3;
  undefined8 *in_GS_OFFSET;
  
  iVar3 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar3 == 0) {
    iVar3 = 1;
  }
  else {
    iVar3 = 0x16;
    if (0xfffffdff < *(int *)(param_2 + 1) - 0x201U) {
      func_0xffffffff8b60bb20(0xffffffff8e2d5900,0,0,0);
      uVar1 = *(uint *)(param_2 + 1);
      uVar2 = *param_2;
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd57f3d,0);
      iVar3 = func_0xffffffff8ac19280(uVar2,&DAT_ffffffff8e2d5920,(ulong)uVar1 << 4);
      if (iVar3 == 0) {
        _DAT_ffffffff8e2d7920 = *(undefined4 *)(param_2 + 1);
        func_0xffffffff8b35e490(&DAT_ffffffff8e2d5920,_DAT_ffffffff8e2d7920,0x10,0xffffffff8ac2ba00)
        ;
      }
      func_0xffffffff8b60c4b0(0xffffffff8e2d5900,0,0);
    }
  }
  return iVar3;
}



/* Input +0x7a8, VA 0xffffffff8ac25f08, JMP target 0xffffffff8b47d930; Evidence ev_6aa82b3349c2f857779f1aedcdeabc2121ab1553066296d2ce5c87979c3e258e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47d930); register/stack arguments unchanged. */

undefined8 handler_body_637(long param_1,int *param_2)

{
  long lVar1;
  int iVar2;
  long lVar3;
  undefined8 uVar4;
  long *in_GS_OFFSET;
  
  if (*(long *)(param_2 + 2) < 0x11) {
    return 0x16;
  }
  if ((*param_2 == 0) || (*param_2 == *(int *)(*(long *)(*in_GS_OFFSET + 8) + 0xbc))) {
    lVar3 = *(long *)(*in_GS_OFFSET + 8);
    func_0xffffffff8ae86a00(lVar3 + 0x148,0,0,0);
  }
  else {
    iVar2 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
    if (iVar2 == 0) {
      return 1;
    }
    lVar3 = func_0xffffffff8aefc170(*param_2);
    if (lVar3 == 0) {
      return 3;
    }
  }
  if (((*(uint *)(lVar3 + 0xb0) & 0x2200) == 0) && (*(int *)(lVar3 + 0xb8) == 1)) {
    *(int *)(lVar3 + 0x358) = *(int *)(lVar3 + 0x358) + 1;
    if ((*(uint *)(lVar3 + 0xb0) & 0x10000000) == 0) {
      func_0xffffffff8aefaa10(lVar3);
    }
    uVar4 = 0;
    func_0xffffffff8ae86fa0(lVar3 + 0x148,0,0,0);
    lVar1 = *(long *)(lVar3 + 0x200);
    if (lVar1 != 0) {
      func_0xffffffff8ae86a00(lVar1 + 0x278,0,0,0);
      *(undefined8 *)(lVar1 + 0x280) = *(undefined8 *)(param_2 + 2);
      func_0xffffffff8ae86fa0(lVar1 + 0x278,0,0,0);
      func_0xffffffff8b051c70(lVar1);
    }
    func_0xffffffff8ae86a00(lVar3 + 0x148,0,0,0);
    iVar2 = *(int *)(lVar3 + 0x358) + -1;
    *(int *)(lVar3 + 0x358) = iVar2;
    if ((iVar2 == 0 & *(byte *)(lVar3 + 0xb1) >> 5) == 1) {
      func_0xffffffff8b5c6910(lVar3 + 0x358);
    }
  }
  else {
    uVar4 = 3;
  }
  func_0xffffffff8ae86fa0(lVar3 + 0x148,0,0,0);
  return uVar4;
}



/* Input +0x7b0, VA 0xffffffff8ac25f10, JMP target 0xffffffff8b07e5c0; Evidence ev_beba8deb3a12b31c1e57ba2d9a1e42d3419b7e51f133ba302cae01f30df352a8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07e5c0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_638(undefined8 param_1,long *param_2)

{
  bool bVar1;
  code *pcVar2;
  long lVar3;
  undefined8 uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  undefined8 *in_GS_OFFSET;
  int iStack_44;
  long lStack_40;
  undefined8 uStack_38;
  undefined8 uStack_30;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  func_0xffffffff8b60b350(0xffffffff8e2d5900,0,0,0);
  if (_DAT_ffffffff8e2d7920 == 0) {
    func_0xffffffff8b60c300(0xffffffff8e2d5900,0,0);
    uVar4 = 0x22;
  }
  else {
    iVar8 = 1;
    if (1 < (int)_DAT_ffffffff8e2d7920) {
      iVar8 = 1;
      uVar6 = _DAT_ffffffff8e2d7920;
      do {
        while (uVar9 = (int)(uVar6 + iVar8) / 2,
              *(long *)(&DAT_ffffffff8e2d5920 + (long)(int)uVar9 * 0x10) <= *param_2) {
          iVar8 = uVar9 + 1;
          if ((int)uVar6 <= iVar8) goto LAB_ffffffff8b07e64f;
        }
        uVar6 = uVar9;
      } while (iVar8 < (int)uVar9);
    }
LAB_ffffffff8b07e64f:
    iStack_44 = 0;
    uStack_38 = *(undefined8 *)((long)iVar8 * 0x10 + -0x71d2a6f0);
    uStack_30 = *(ulong *)((long)iVar8 * 0x10 + -0x71d2a6e8);
    if (-1 < _DAT_ffffffff8e4305b0) {
      uVar6 = iVar8 - 1;
      if (0 < iVar8) {
        iVar7 = 0;
        iVar5 = iVar8;
        do {
          iVar10 = *(int *)((ulong)(iVar5 - 1) * 0x10 + -0x71d2a6d4);
          if (iVar10 != 0) {
            iStack_44 = iVar10;
            if (_DAT_ffffffff8e2d7920 <= uVar6) goto LAB_ffffffff8b07e705;
            goto LAB_ffffffff8b07e6d6;
          }
          iVar7 = iVar7 + 1;
          iVar10 = iVar5 + -1;
          bVar1 = 0 < iVar5;
          iVar5 = iVar10;
        } while (iVar10 != 0 && bVar1);
      }
      iVar7 = 0x201;
      if (uVar6 < _DAT_ffffffff8e2d7920) {
LAB_ffffffff8b07e6d6:
        iVar5 = 0;
        do {
          iVar10 = *(int *)((long)(int)(uVar6 + iVar5) * 0x10 + -0x71d2a6d4);
          if (iVar10 != 0) {
            if (iVar5 < iVar7) {
              iStack_44 = iVar10;
            }
            break;
          }
          iVar5 = iVar5 + 1;
        } while ((_DAT_ffffffff8e2d7920 - iVar8) + 1 != iVar5);
      }
    }
LAB_ffffffff8b07e705:
    func_0xffffffff8b60c300(0xffffffff8e2d5900,0,0);
    if (_DAT_ffffffff8e4305b0 < 0) {
      lVar3 = 0;
      uStack_30 = uStack_30 & 0xffffffff;
    }
    else {
      lVar3 = (long)uStack_30._4_4_;
    }
    lStack_40 = lVar3 + *param_2 + (long)(int)uStack_30;
    lVar3 = param_2[1];
    if (lVar3 != 0) {
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar4 = func_0xffffffff8ac191d0(&lStack_40,lVar3,8);
      if ((int)uVar4 != 0) goto LAB_ffffffff8b07e7dc;
    }
    lVar3 = param_2[2];
    if (lVar3 != 0) {
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar4 = func_0xffffffff8ac191d0(&uStack_38,lVar3,0x10);
      if ((int)uVar4 != 0) goto LAB_ffffffff8b07e7dc;
    }
    lVar3 = param_2[3];
    if (lVar3 != 0) {
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar4 = func_0xffffffff8ac191d0(&iStack_44,lVar3,4);
      if ((int)uVar4 != 0) goto LAB_ffffffff8b07e7dc;
    }
    uVar4 = 0;
  }
LAB_ffffffff8b07e7dc:
  if (_DAT_ffffffff8e2dc310 != lStack_28) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar2 = (code *)invalidInstructionException();
    (*pcVar2)();
  }
  return uVar4;
}



/* Input +0x7b8, VA 0xffffffff8ac25f18, JMP target 0xffffffff8b07e800; Evidence ev_0299be0325c3e1108d4052967f411df5b831d74aa56f37e136d126999c1fb5f7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07e800); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_639(undefined8 param_1,long *param_2)

{
  int iVar1;
  int iVar2;
  code *pcVar3;
  undefined8 uVar4;
  bool bVar5;
  ulong uVar6;
  undefined1 *puVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  ulong uVar11;
  long lVar12;
  long lVar13;
  undefined8 *in_GS_OFFSET;
  int iStack_44;
  long lStack_40;
  undefined8 uStack_38;
  undefined8 uStack_30;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  iStack_44 = 0;
  func_0xffffffff8b60b350(0xffffffff8e2d5900,0,0,0);
  if (_DAT_ffffffff8e2d7920 == 0) {
    func_0xffffffff8b60c300(0xffffffff8e2d5900,0,0);
    uVar4 = 0x22;
  }
  else {
    uVar6 = 1;
    if (1 < (int)_DAT_ffffffff8e2d7920) {
      uVar6 = 1;
      uVar10 = _DAT_ffffffff8e2d7920;
      do {
        while( true ) {
          uVar9 = (int)(uVar10 + (int)uVar6) / 2;
          lVar12 = (long)(int)uVar9 * 0x10;
          if (_DAT_ffffffff8e4305b0 < 0) {
            lVar13 = 0;
          }
          else {
            lVar13 = (long)*(int *)(lVar12 + -0x71d2a6d4);
          }
          if ((long)*(int *)(&DAT_ffffffff8e2d5928 + lVar12) +
              *(long *)(&DAT_ffffffff8e2d5920 + lVar12) + lVar13 <= *param_2) break;
          uVar10 = uVar9;
          if ((int)uVar9 <= (int)uVar6) goto LAB_ffffffff8b07e8cc;
        }
        uVar6 = (ulong)(uVar9 + 1);
      } while ((int)(uVar9 + 1) < (int)uVar10);
    }
LAB_ffffffff8b07e8cc:
    uVar10 = (uint)uVar6;
    uVar9 = uVar10 - 1;
    if (_DAT_ffffffff8e4305b0 < 0) {
      uStack_38 = *(undefined8 *)(&DAT_ffffffff8e2d5920 + (long)(int)uVar9 * 0x10);
      uStack_30 = *(ulong *)(&DAT_ffffffff8e2d5928 + (long)(int)uVar9 * 0x10);
    }
    else {
      iVar1 = (int)param_2[1];
      if ((int)uVar10 < 2 || iVar1 < 0) {
        lVar12 = (long)(int)uVar9 * 0x10;
        uStack_38 = *(undefined8 *)(&DAT_ffffffff8e2d5920 + lVar12);
        puVar7 = &DAT_ffffffff8e2d5920 + lVar12;
        uStack_30 = *(ulong *)(&DAT_ffffffff8e2d5928 + lVar12);
        goto joined_r0xffffffff8b07e9cb;
      }
      uVar11 = (ulong)uVar9;
      uVar10 = uVar10 - 2;
      iVar2 = *(int *)((ulong)uVar10 * 0x10 + -0x71d2a6d4);
      if (*param_2 <
          (long)*(int *)(&DAT_ffffffff8e2d5928 + (ulong)uVar10 * 0x10) +
          *(long *)(&DAT_ffffffff8e2d5920 + uVar11 * 0x10) + (long)iVar2) {
        uVar8 = uVar9;
        if (iVar2 == 0 && iVar1 == 0) {
          uVar8 = uVar10;
        }
        if (iVar2 < 1) {
          uVar10 = uVar8;
        }
        if (iVar1 == 0) {
          uVar10 = uVar8;
        }
        uVar11 = (ulong)uVar10;
      }
      lVar12 = uVar11 * 0x10;
      uStack_38 = *(undefined8 *)(&DAT_ffffffff8e2d5920 + lVar12);
      puVar7 = &DAT_ffffffff8e2d5920 + lVar12;
      uStack_30 = *(ulong *)(&DAT_ffffffff8e2d5928 + lVar12);
      do {
        uVar10 = (int)uVar6 - 1;
        uVar6 = (ulong)uVar10;
        iStack_44 = *(int *)(uVar6 * 0x10 + -0x71d2a6d4);
        if (iStack_44 != 0) {
          bVar5 = (int)uVar9 <= (int)uVar10;
          goto joined_r0xffffffff8b07ea0a;
        }
joined_r0xffffffff8b07e9cb:
      } while (0 < (int)uVar10);
      iStack_44 = 0;
      bVar5 = false;
joined_r0xffffffff8b07ea0a:
      if ((uVar9 < _DAT_ffffffff8e2d7920) && (*(int *)(puVar7 + 0xc) != 0 && !bVar5)) {
        iStack_44 = *(int *)(puVar7 + 0xc);
      }
    }
    func_0xffffffff8b60c300(0xffffffff8e2d5900,0,0);
    if (_DAT_ffffffff8e4305b0 < 0) {
      lVar12 = 0;
      uStack_30 = uStack_30 & 0xffffffff;
    }
    else {
      lVar12 = (long)uStack_30._4_4_;
    }
    lStack_40 = *param_2 - ((int)uStack_30 + lVar12);
    lVar12 = param_2[2];
    if (lVar12 != 0) {
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar4 = func_0xffffffff8ac191d0(&lStack_40,lVar12,8);
      if ((int)uVar4 != 0) goto LAB_ffffffff8b07eaf8;
    }
    lVar12 = param_2[3];
    if (lVar12 != 0) {
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar4 = func_0xffffffff8ac191d0(&uStack_38,lVar12,0x10);
      if ((int)uVar4 != 0) goto LAB_ffffffff8b07eaf8;
    }
    lVar12 = param_2[4];
    if (lVar12 != 0) {
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar4 = func_0xffffffff8ac191d0(&iStack_44,lVar12,4);
      if ((int)uVar4 != 0) goto LAB_ffffffff8b07eaf8;
    }
    uVar4 = 0;
  }
LAB_ffffffff8b07eaf8:
  if (_DAT_ffffffff8e2dc310 == lStack_28) {
    return uVar4;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar3 = (code *)invalidInstructionException();
  (*pcVar3)();
}



/* Input +0x7c0, VA 0xffffffff8ac25f20, JMP target 0xffffffff8b450e10; Evidence ev_c3986da2e65569d0901749cad39df4022f7c785201fc76a778d29e94bc389464 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b450e10); register/stack arguments unchanged. */

undefined8 handler_body_640(void)

{
  return 0;
}



/* Input +0x7c8, VA 0xffffffff8ac25f28, JMP target 0xffffffff8ae62de0; Evidence ev_e5b84a8edadcaee334cef5790cf4ccb76eb5ffb72bba7ca6dff0722a415ea2d3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae62de0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 handler_body_641(long param_1,undefined4 *param_2)

{
  code *pcVar1;
  long lVar2;
  int iVar3;
  long lVar4;
  long *plVar5;
  ulong uVar6;
  undefined8 uVar7;
  undefined8 *in_GS_OFFSET;
  long lStack_100;
  ulong uStack_f8;
  long lStack_f0;
  ulong uStack_e8;
  undefined4 uStack_70;
  undefined4 uStack_6c;
  long lStack_68;
  ulong uStack_60;
  long lStack_58;
  ulong uStack_50;
  ulong uStack_48;
  ulong uStack_40;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  iVar3 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar3 == 0) {
    uVar7 = 0x4e;
  }
  else {
    sub_4a2ce0();
    func_0xffffffff8ac18ff0(&uStack_70,0x38);
    lVar4 = func_0xffffffff8aefc170(*param_2);
    if (lVar4 == 0) {
      lVar4 = *(long *)(param_1 + 8);
      plVar5 = (long *)func_0xffffffff8b552420(*param_2,*(undefined4 *)(lVar4 + 0xbc));
      if (plVar5 != (long *)0x0) {
        func_0xffffffff8ae87190(lVar4 + 0x168,0,0,0);
        func_0xffffffff8ae878b0(plVar5,0,0xffffffff8bc6a1cd,0x68b);
        func_0xffffffff8ae61a20(plVar5,&lStack_100);
        func_0xffffffff8ae87520(*plVar5 + 0x18,0,0,0);
        uStack_60 = uStack_f8;
        lStack_68 = lStack_100;
        uStack_50 = uStack_e8;
        lStack_58 = lStack_f0;
        uVar6 = func_0xffffffff8b4909c0(*(undefined8 *)(lVar4 + 0x2c0));
        func_0xffffffff8ae87520(lVar4 + 0x168,0,0,0);
        uStack_48 = uVar6 / 1000000;
        uStack_40 = uVar6 % 1000000;
        func_0xffffffff8ae86fa0(lVar4 + 0x148,0,0,0);
        uStack_70 = *(undefined4 *)(lVar4 + 0xbc);
        uStack_6c = *param_2;
        uVar7 = *(undefined8 *)(param_2 + 2);
        func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
        uVar7 = func_0xffffffff8ac191d0(&uStack_70,uVar7,0x38);
        goto LAB_ffffffff8ae63176;
      }
    }
    else {
      if (*(int *)(lVar4 + 0xb8) == 1) {
        func_0xffffffff8ae87190(lVar4 + 0x168,0,0,0);
        for (plVar5 = *(long **)(lVar4 + 0x10); plVar5 != (long *)0x0; plVar5 = (long *)plVar5[2]) {
          func_0xffffffff8ae878b0(plVar5,0,0xffffffff8bc6a1cd,0x6a8);
          func_0xffffffff8ae61a20(plVar5);
          func_0xffffffff8ae87520(*plVar5 + 0x18,0,0,0);
          uStack_60 = uStack_60 + uStack_f8;
          lVar2 = lStack_100;
          if (999999 < (long)uStack_60) {
            uStack_60 = uStack_60 % 1000000;
            lVar2 = lStack_100 + 1;
          }
          lStack_68 = lVar2 + lStack_68;
          uStack_50 = uStack_50 + uStack_e8;
          lVar2 = lStack_f0;
          if (999999 < (long)uStack_50) {
            uStack_50 = uStack_50 % 1000000;
            lVar2 = lStack_f0 + 1;
          }
          lStack_58 = lStack_58 + lVar2;
        }
        uVar6 = func_0xffffffff8b4909c0(*(undefined8 *)(lVar4 + 0x2c0));
        func_0xffffffff8ae87520(lVar4 + 0x168,0,0,0);
        uStack_48 = uVar6 / 1000000;
        uStack_40 = uVar6 % 1000000;
        func_0xffffffff8ae86fa0(lVar4 + 0x148,0,0,0);
        uStack_70 = *param_2;
        uVar7 = *(undefined8 *)(param_2 + 2);
        func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
        uVar7 = func_0xffffffff8ac191d0(&uStack_70,uVar7,0x38);
        goto LAB_ffffffff8ae63176;
      }
      func_0xffffffff8ae86fa0(lVar4 + 0x148,0,0,0);
    }
    uVar7 = 3;
  }
LAB_ffffffff8ae63176:
  if (_DAT_ffffffff8e2dc310 == lStack_38) {
    return uVar7;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0x7d0, VA 0xffffffff8ac25f30, JMP target 0xffffffff8b47dad0; Evidence ev_4798e6510b262229d89aad676f279b5d008601981fab7469c7985c4d7b8b526c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47dad0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

ulong handler_body_642(long param_1,undefined4 *param_2)

{
  long lVar1;
  char cVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long lVar6;
  undefined8 uVar7;
  code *pcVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  long lVar12;
  ulong uVar13;
  long lVar14;
  long lVar15;
  long lVar16;
  long lVar17;
  long lVar18;
  ulong uVar19;
  undefined8 *in_GS_OFFSET;
  int iStack_a4;
  undefined1 auStack_a0 [32];
  undefined8 uStack_80;
  undefined8 uStack_78;
  long lStack_70;
  uint uStack_68;
  undefined4 uStack_64;
  undefined4 uStack_60;
  int iStack_5c;
  uint uStack_58;
  undefined8 uStack_54;
  undefined8 uStack_4c;
  undefined8 uStack_44;
  int iStack_3c;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  iVar9 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar9 == 0) {
    uVar13 = 1;
  }
  else {
    lVar12 = func_0xffffffff8aefc170(*param_2);
    uVar13 = 2;
    if (lVar12 != 0) {
      if ((*(uint *)(lVar12 + 0xb0) & 0x2000) == 0) {
        *(int *)(lVar12 + 0x358) = *(int *)(lVar12 + 0x358) + 1;
        if ((*(uint *)(lVar12 + 0xb0) & 0x10000000) == 0) {
          func_0xffffffff8aefaa10(lVar12);
        }
        lVar1 = lVar12 + 0x148;
        func_0xffffffff8ae86fa0(lVar1,0,0,0);
        lVar3 = *(long *)(lVar12 + 0x200);
        func_0xffffffff8ac86820(lVar3,0,0);
        iStack_a4 = 0;
        func_0xffffffff8ac18ff0(auStack_a0,0x68);
        for (lVar4 = *(long *)(lVar3 + 8); lVar4 != lVar3; lVar4 = *(long *)(lVar4 + 8)) {
          if ((*(short *)(lVar4 + 0x66) != 0) && ((*(byte *)(lVar4 + 0x60) & 2) == 0)) {
            lVar5 = *(long *)(lVar4 + 0x50);
            uStack_68 = (uint)*(ushort *)(lVar4 + 100);
            uVar10 = *(uint *)(lVar4 + 0x60);
            if ((uVar10 & 0x20) != 0) {
              uStack_68 = uStack_68 | 0x10000;
              uVar10 = *(uint *)(lVar4 + 0x60);
            }
            if ((uVar10 & 0x1000) != 0) {
              uStack_68 = uStack_68 | 0x20000;
            }
            uStack_80 = *(undefined8 *)(lVar4 + 0x20);
            uStack_78 = *(undefined8 *)(lVar4 + 0x28);
            if ((lVar5 == 0) ||
               (((*(byte *)(lVar5 + 0x9d) < 0xb &&
                 ((0x587U >> (*(byte *)(lVar5 + 0x9d) & 0x1f) & 1) != 0)) &&
                ((*(byte *)(lVar5 + 0xa2) & 1) == 0)))) {
              if (*(short *)(lVar4 + 0x66) == 0) {
                iStack_3c = 0;
              }
              else {
                iStack_3c = (int)*(char *)(lVar4 + 0x14c);
              }
              if (lVar5 != 0) goto LAB_ffffffff8b47dc7a;
              func_0xffffffff8ac18ff0(auStack_a0,0x68);
            }
            else {
              iStack_3c = 0;
LAB_ffffffff8b47dc7a:
              lVar18 = lVar5 + 0x18;
              func_0xffffffff8b1946a0(lVar18,0,0);
              if ((byte)(*(char *)(lVar5 + 0x9d) - 3U) < 2) {
                func_0xffffffff8b194eb0(lVar18,0,0);
                goto LAB_ffffffff8b47dbd0;
              }
              uStack_64 = *(undefined4 *)(lVar5 + 0x130);
              uStack_60 = *(undefined4 *)(lVar5 + 0x138);
              iVar9 = 0;
              func_0xffffffff8b194eb0(lVar18,0,0);
              uVar13 = *(ulong *)(lVar4 + 0x20) & 0xffffffffffffc000;
              uVar19 = *(long *)(lVar4 + 0x28) + 0x3fffU & 0xffffffffffffc000;
              if (uVar13 < uVar19) {
                iVar9 = 0;
                do {
                  lVar14 = func_0xffffffff8b29e3e0(*(undefined8 *)(lVar3 + 0x1d8),uVar13);
                  iVar9 = (iVar9 + 1) - (uint)(lVar14 == 0);
                  uVar13 = uVar13 + 0x4000;
                } while (uVar13 < uVar19);
              }
              lStack_70 = (long)(int)((uint)lVar5 ^ 0x8e5b6e18);
              uStack_58 = (uint)*(byte *)(lVar5 + 0x9d);
              uStack_54 = 0;
              uStack_4c = 0;
              uStack_44 = 0;
              uVar10 = (uint)((ulong)(*(long *)(lVar4 + 0x28) - *(long *)(lVar4 + 0x20)) >> 0xe);
              iStack_5c = iVar9;
              if (0 < (int)uVar10) {
                uVar13 = 0;
LAB_ffffffff8b47ddd8:
                lVar14 = *(long *)(lVar4 + 0x58);
                lVar17 = (long)((int)uVar13 << 0xe);
                func_0xffffffff8b1946a0(lVar18,0,0);
                lVar15 = func_0xffffffff8b5497e0(lVar5);
                lVar16 = lVar5;
                while (lVar15 == 0) {
                  lVar6 = *(long *)(lVar16 + 0xb0);
                  if (lVar6 == 0) {
                    func_0xffffffff8b194eb0(lVar16 + 0x18,0,0);
                    lVar14 = *(long *)(lVar4 + 0x58);
                    func_0xffffffff8b1946a0(lVar18,0,0);
                    cVar2 = *(char *)(lVar5 + 0x9d);
                    lVar16 = lVar5;
                    goto joined_r0xffffffff8b47df6d;
                  }
                  lVar14 = lVar14 + *(long *)(lVar16 + 0xb8);
                  func_0xffffffff8b1946a0(lVar6 + 0x18,0,0);
                  func_0xffffffff8b194eb0(lVar16 + 0x18,0,0);
                  lVar15 = func_0xffffffff8b5497e0(lVar6);
                  lVar16 = lVar6;
                }
                func_0xffffffff8b54d8a0(lVar15);
                if (*(int *)(lVar15 + 0x70) == 0) {
                  uStack_4c = CONCAT44(uStack_4c._4_4_ + 1,(int)uStack_4c);
                  cVar2 = *(char *)(lVar15 + 0x66);
                }
                else {
                  uStack_4c = CONCAT44(uStack_4c._4_4_,(int)uStack_4c + 1);
                  cVar2 = *(char *)(lVar15 + 0x66);
                }
                if (cVar2 == '\x01') {
                  uStack_44 = CONCAT44(uStack_44._4_4_,(int)uStack_44 + 1);
                }
                if (*(int *)(lVar15 + 0x70) == 0) {
                  if ((*(long *)(lVar15 + 0x20) == 0) ||
                     (*(char *)(*(long *)(lVar15 + 0x20) + 0x9d) == '\0')) {
LAB_ffffffff8b47dda0:
                    uStack_44 = CONCAT44(uStack_44._4_4_ + 1,(int)uStack_44);
                  }
                  else if (*(char *)(lVar16 + 0x9d) == '\x01') {
                    pcVar8 = *(code **)(_DAT_ffffffff8c483918 + 0x38);
                    if (0xd < (-(long)pcVar8 - 0x753d47b8U >> 3 | -(long)pcVar8 << 0x3d)) {
                      func_0xffffffff8ae0f8c0(0xffffffff8d248d60,pcVar8);
                    }
                    iVar9 = (*pcVar8)(lVar16,lVar14 + lVar17 >> 0xe,0);
                    if (iVar9 == 0) goto LAB_ffffffff8b47dda0;
                  }
                }
                goto LAB_ffffffff8b47dda3;
              }
            }
LAB_ffffffff8b47e03b:
            func_0xffffffff8b317b70(auStack_a0,lVar4 + 0x150,0x20);
            iVar9 = iStack_a4;
            lVar18 = (long)iStack_a4;
            lVar5 = *(long *)(param_2 + 4);
            if ((lVar5 != 0) && (iStack_a4 < (int)param_2[2])) {
              func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
              iVar11 = func_0xffffffff8ac191d0(auStack_a0,lVar5 + lVar18 * 0x68,0x68);
              if (iVar11 != 0) break;
            }
            iStack_a4 = iVar9 + 1;
          }
LAB_ffffffff8b47dbd0:
        }
        func_0xffffffff8ac86870(lVar3,0,0);
        func_0xffffffff8ae86a00(lVar1,0,0,0);
        iVar9 = *(int *)(lVar12 + 0x358) + -1;
        *(int *)(lVar12 + 0x358) = iVar9;
        if ((iVar9 == 0 & *(byte *)(lVar12 + 0xb1) >> 5) == 1) {
          func_0xffffffff8b5c6910(lVar12 + 0x358);
        }
        func_0xffffffff8ae86fa0(lVar1,0,0,0);
        uVar7 = *(undefined8 *)(param_2 + 6);
        func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
        uVar13 = func_0xffffffff8ac191d0(&iStack_a4,uVar7,4);
        if ((*(long *)(param_2 + 4) != 0) &&
           (uVar13 = uVar13 & 0xffffffff, (int)param_2[2] < iStack_a4)) {
          uVar13 = 0xc;
        }
      }
      else {
        func_0xffffffff8ae86fa0(lVar12 + 0x148,0,0,0);
        uVar13 = 2;
      }
    }
  }
  if (_DAT_ffffffff8e2dc310 == lStack_38) {
    return uVar13;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar8 = (code *)invalidInstructionException();
  (*pcVar8)();
joined_r0xffffffff8b47df6d:
  if (cVar2 == '\x01') {
    pcVar8 = *(code **)(_DAT_ffffffff8c483918 + 0x38);
    if (0xd < (-(long)pcVar8 - 0x753d47b8U >> 3 | -(long)pcVar8 << 0x3d)) {
      func_0xffffffff8ae0f8c0(0xffffffff8d248d60,pcVar8);
    }
    iVar9 = (*pcVar8)(lVar16,lVar14 + lVar17 >> 0xe,0,0);
    if (iVar9 != 0) {
      uStack_54 = CONCAT44(uStack_54._4_4_ + 1,(int)uStack_54);
      goto LAB_ffffffff8b47dda3;
    }
  }
  lVar15 = *(long *)(lVar16 + 0xb0);
  if (lVar15 == 0) goto LAB_ffffffff8b47e006;
  lVar14 = lVar14 + *(long *)(lVar16 + 0xb8);
  func_0xffffffff8b1946a0(lVar15 + 0x18,0,0);
  func_0xffffffff8b194eb0(lVar16 + 0x18,0,0);
  cVar2 = *(char *)(lVar15 + 0x9d);
  lVar16 = lVar15;
  goto joined_r0xffffffff8b47df6d;
LAB_ffffffff8b47e006:
  uStack_54 = CONCAT44(uStack_54._4_4_,(int)uStack_54 + 1);
LAB_ffffffff8b47dda3:
  func_0xffffffff8b194eb0(lVar16 + 0x18,0,0);
  uVar13 = uVar13 + 1;
  if (uVar13 == (uVar10 & 0x7fffffff)) goto LAB_ffffffff8b47e03b;
  goto LAB_ffffffff8b47ddd8;
}



/* Input +0x7d8, VA 0xffffffff8ac25f38, JMP target 0xffffffff8b3f7660; Evidence ev_3d64cd7693bd60b6d49fecc718bd44be424ba54896cbfc279083e6b20ed40ba3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f7660); register/stack arguments unchanged. */

undefined8 sub_a37660(long param_1,uint *param_2)

{
  uint *puVar1;
  
  func_0xffffffff8ac1d410(0xffffffff8bd218e2,*param_2);
  puVar1 = (uint *)(*(long *)(param_1 + 8) + 0xa34);
  *puVar1 = *puVar1 | *param_2;
  return 0;
}



/* Input +0x7e0, VA 0xffffffff8ac25f40, JMP target 0xffffffff8b47e1c0; Evidence ev_27504ee7e498f06cfe34f87692bdf35f1daeadd868161c6274c80a01a8271efd */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47e1c0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abe1c0(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 *in_GS_OFFSET;
  undefined1 auStack_420 [1016];
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  iVar2 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar2 == 0) {
    uVar3 = 1;
  }
  else {
    func_0xffffffff8ac18ff0(auStack_420,0x3f8);
    uVar3 = *param_2;
    func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
    uVar3 = func_0xffffffff8ac191d0(auStack_420,uVar3,0x3f8);
  }
  if (_DAT_ffffffff8e2dc310 == lStack_28) {
    return uVar3;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0x7e8, VA 0xffffffff8ac25f48, JMP target 0xffffffff8b47e7b0; Evidence ev_bd87842d69d96b63f1ac4c984344aff2373c4de6e92ec72bd13d8ac6e7935638 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47e7b0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abe7b0(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  int iStack_2c;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  iVar2 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar2 == 0) {
    uVar3 = 1;
  }
  else {
    iStack_2c = 0;
    uVar3 = sub_abe260(param_1,*param_2,4,&iStack_2c);
    *(long *)(param_1 + 0x408) = (long)iStack_2c;
  }
  if (_DAT_ffffffff8e2dc310 == lStack_28) {
    return uVar3;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0x7f0, VA 0xffffffff8ac25f50, JMP target 0xffffffff8b3b81f0; Evidence ev_38992dca2ddd1724dbfdec81bda48eef81258e5e6e19df10401dc8ffe8e78ff4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3b81f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3b81f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x7f8, VA 0xffffffff8ac25f58, JMP target 0xffffffff8b5a9510; Evidence ev_805e775aea09c7b3d7796ebdbf845026670e35d7bd3812145500f0480286b2ea */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5a9510); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5a9510(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x800, VA 0xffffffff8ac25f60, JMP target 0xffffffff8b367d10; Evidence ev_f62ff92f01a09e3e75cccb36812c734d0907271222e1acb231f8c2b0496784af */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b367d10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b367d10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x808, VA 0xffffffff8ac25f68, JMP target 0xffffffff8b369560; Evidence ev_f5b773809125f55f42a2908ea0b18de9e44a208a0a0abbb4864a260929e2f67e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b369560); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b369560(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x810, VA 0xffffffff8ac25f70, JMP target 0xffffffff8b369e10; Evidence ev_f698b27e379b94822718be1627289b1544a91dce16110d51fe8bbfde94fb3b4c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b369e10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b369e10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x818, VA 0xffffffff8ac25f78, JMP target 0xffffffff8b369f40; Evidence ev_2ec1a1251dc535563b19eb28de190b91f4c9683eb251d6eed5e6269bd2db9650 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b369f40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b369f40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x820, VA 0xffffffff8ac25f80, JMP target 0xffffffff8b2bb440; Evidence ev_fc4bd21907bbcde63d0427cff66be0c481210d3ccf79fb56a3b148aa5cd389e1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bb440); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bb440(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x828, VA 0xffffffff8ac25f88, JMP target 0xffffffff8ae631a0; Evidence ev_91fa8140a29e7ac607865a8f1f043ea86a2fad8b51a7dccefac62381f91963f4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae631a0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_4a31a0(long param_1,long *param_2)

{
  code *pcVar1;
  long lVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  long *plVar8;
  long *plVar9;
  ulong uVar10;
  long *plVar11;
  int iStack_7c;
  long lStack_78;
  ulong uStack_70;
  long *plStack_68;
  undefined4 uStack_60;
  undefined8 uStack_58;
  ulong uStack_50;
  undefined8 uStack_48;
  long lStack_40;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  iVar3 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar3 == 0) {
    iVar3 = 0x4e;
    goto LAB_ffffffff8ae63602;
  }
  if (*param_2 == 0) {
    iVar5 = 0;
    func_0xffffffff8b60b350(0xffffffff8df49e60,0,0,0);
    if (_DAT_ffffffff8df49e80 != (long *)0x0) {
      iVar5 = 0;
      plVar11 = _DAT_ffffffff8df49e80;
      do {
        func_0xffffffff8ae86a00(plVar11 + 0x29,0,0,0);
        if ((1 < *(uint *)(plVar11 + 0xba)) && ((int)plVar11[0x17] == 1)) {
          for (plVar8 = (long *)plVar11[2]; plVar8 != (long *)0x0; plVar8 = (long *)plVar8[2]) {
            func_0xffffffff8ae878b0(plVar8,0,0xffffffff8bc6a1cd);
            if ((plVar8[0xb6] != 0) || (plVar8[0xb8] != 0)) {
              iVar5 = iVar5 + 1;
            }
            func_0xffffffff8ae87520(*plVar8 + 0x18,0,0);
          }
        }
        func_0xffffffff8ae86fa0(plVar11 + 0x29,0,0);
        plVar11 = (long *)*plVar11;
      } while (plVar11 != (long *)0x0);
    }
    func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
  }
  else {
    iVar4 = func_0xffffffff8b142a40(param_2[1]);
    if (iVar4 == -1) {
      iVar3 = 0xe;
      goto LAB_ffffffff8ae63602;
    }
    iVar3 = 0x16;
    if (iVar4 - 0x2711U < 0xffffd8f0) goto LAB_ffffffff8ae63602;
    lStack_78 = *param_2;
    iVar5 = 0;
    uStack_70 = (ulong)(uint)(iVar4 * 0x28);
    plStack_68 = &lStack_78;
    uStack_60 = 1;
    uStack_58 = 0;
    uStack_48 = 0;
    uStack_50 = uStack_70;
    lStack_40 = param_1;
    func_0xffffffff8b60b350(0xffffffff8df49e60,0,0,0);
    if (_DAT_ffffffff8df49e80 != (long *)0x0) {
      iVar5 = 0;
      plVar11 = _DAT_ffffffff8df49e80;
      do {
        plVar8 = plVar11 + 0x29;
        func_0xffffffff8ae86a00(plVar8,0,0,0);
        if ((1 < *(uint *)(plVar11 + 0xba)) && ((int)plVar11[0x17] == 1)) {
LAB_ffffffff8ae632da:
          lVar2 = plVar11[0x169];
          func_0xffffffff8ae86fa0(plVar8,0,0);
          puVar6 = (undefined4 *)
                   func_0xffffffff8b5c8b50((long)(int)lVar2 * 0x28,0xffffffff8c488120,0x102);
          func_0xffffffff8ae86a00(plVar8,0,0,0);
          if ((int)lVar2 < (int)plVar11[0x169]) goto code_r0xffffffff8ae63321;
          func_0xffffffff8ae87190(plVar11 + 7,0,0);
          plVar9 = (long *)plVar11[2];
          if (plVar9 == (long *)0x0) {
            uVar10 = 0;
          }
          else {
            iStack_7c = 0;
            puVar7 = puVar6;
            do {
              func_0xffffffff8ae878b0(plVar9,0,0xffffffff8bc6a1cd);
              if ((plVar9[0xb6] == 0) && (plVar9[0xb8] == 0)) {
                func_0xffffffff8ae87520(*plVar9 + 0x18,0,0);
              }
              else {
                *puVar7 = *(undefined4 *)((long)plVar11 + 0xbc);
                puVar7[1] = *(undefined4 *)((long)plVar9 + 0x9c);
                *(long *)(puVar7 + 2) = plVar9[0xb6];
                *(long *)(puVar7 + 4) = plVar9[0xb7];
                *(long *)(puVar7 + 6) = plVar9[0xb8];
                *(long *)(puVar7 + 8) = plVar9[0xb9];
                func_0xffffffff8ae87520(*plVar9 + 0x18,0,0);
                iStack_7c = iStack_7c + 1;
                puVar7 = puVar7 + 10;
                iVar5 = iVar5 + 1;
              }
              plVar9 = (long *)plVar9[2];
            } while (plVar9 != (long *)0x0);
            uVar10 = (long)iStack_7c * 0x28;
          }
          func_0xffffffff8ae87520(plVar11 + 7,0,0);
          func_0xffffffff8ae86fa0(plVar8,0,0);
          if (uStack_50 < uVar10) {
            uVar10 = uStack_50;
          }
          iVar3 = func_0xffffffff8b142520(puVar6,uVar10 & 0xffffffff,&plStack_68);
          func_0xffffffff8b5c8df0(puVar6);
          if (iVar3 != 0) {
            func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
            goto LAB_ffffffff8ae63602;
          }
          goto LAB_ffffffff8ae6329e;
        }
LAB_ffffffff8ae63290:
        func_0xffffffff8ae86fa0(plVar8,0,0);
LAB_ffffffff8ae6329e:
        plVar11 = (long *)*plVar11;
      } while (plVar11 != (long *)0x0);
    }
    func_0xffffffff8b60c300(0xffffffff8df49e60,0,0);
  }
  iVar5 = func_0xffffffff8ac19790(param_2[1],iVar5);
  iVar3 = 0xe;
  if (iVar5 == 0) {
    iVar3 = 0;
  }
LAB_ffffffff8ae63602:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  return iVar3;
code_r0xffffffff8ae63321:
  func_0xffffffff8ae86fa0(plVar8,0,0);
  func_0xffffffff8b5c8df0(puVar6);
  func_0xffffffff8ae86a00(plVar8,0,0,0);
  if ((int)plVar11[0x17] != 1) goto LAB_ffffffff8ae63290;
  goto LAB_ffffffff8ae632da;
}



/* Input +0x830, VA 0xffffffff8ac25f90, JMP target 0xffffffff8b47e8b0; Evidence ev_dd831ee0d272d67af73c859afc89e869a2308fcb242cd2934e430f03f5443c8d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47e8b0); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abe8b0(long param_1,uint *param_2)

{
  uint uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  code *pcVar4;
  int iVar5;
  undefined8 uVar6;
  uint uVar7;
  long *in_GS_OFFSET;
  uint uStack_40;
  uint uStack_3c;
  long lStack_38;
  
  lStack_38 = _DAT_ffffffff8e2dc310;
  uVar2 = *(undefined8 *)(param_2 + 6);
  uVar7 = *param_2;
  uVar1 = param_2[2];
  uVar3 = *(undefined8 *)(param_2 + 4);
  iVar5 = func_0xffffffff8b48c9a0(0);
  if ((iVar5 != 0) || (uVar6 = 2, 0x4ffffff < *(uint *)(*(long *)(*in_GS_OFFSET + 8) + 0x5d4))) {
    if (uVar7 == 0xffffffff) {
      uVar7 = *(uint *)(*(long *)(param_1 + 8) + 0x5c0);
    }
    else {
      iVar5 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
      if (iVar5 == 0) {
        uVar6 = 1;
        goto LAB_ffffffff8b47e9f8;
      }
    }
    uVar6 = 0x16;
    if (uVar7 < 0xb) {
      if (uVar1 == 2) {
        func_0xffffffff8b3a3650(uVar7,&uStack_3c,&uStack_40);
        if ((*(byte *)(*(long *)(*(long *)(param_1 + 8) + 0x200) + 0x244) & 2) != 0) {
          uVar7 = uStack_3c + 3;
          if (-1 < (int)uStack_3c) {
            uVar7 = uStack_3c;
          }
          uStack_3c = (int)uVar7 >> 2;
          uVar7 = uStack_40 + 3;
          if (-1 < (int)uStack_40) {
            uVar7 = uStack_40;
          }
          uStack_40 = (int)uVar7 >> 2;
        }
      }
      else {
        if (uVar1 != 1) goto LAB_ffffffff8b47e9f8;
        func_0xffffffff8b2ad4e0(uVar7,&uStack_3c,&uStack_40);
      }
      iVar5 = func_0xffffffff8ac19790(uVar3,~((int)uStack_3c >> 0x1f) & uStack_3c);
      if (iVar5 == -1) {
        uVar6 = 0xe;
      }
      else {
        iVar5 = func_0xffffffff8ac19790(uVar2,~((int)uStack_40 >> 0x1f) & uStack_40);
        uVar6 = 0xe;
        if (iVar5 != -1) {
          uVar6 = 0;
        }
      }
    }
  }
LAB_ffffffff8b47e9f8:
  if (_DAT_ffffffff8e2dc310 != lStack_38) {
    func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
    pcVar4 = (code *)invalidInstructionException();
    (*pcVar4)();
  }
  return uVar6;
}



/* Input +0x838, VA 0xffffffff8ac25f98, JMP target 0xffffffff8b36b1f0; Evidence ev_72f4da5b8bd5b72a5862e5b2be4fec520113628f5a8afdd9f51c33ffa8bb3f99 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b36b1f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b36b1f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x840, VA 0xffffffff8ac25fa0, JMP target 0xffffffff8b47b980; Evidence ev_216fd71d36ba58686d8ce8b86c578045450d8b9dac37c7d4e37bce87df3d2167 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47b980); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47b980(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x848, VA 0xffffffff8ac25fa8, JMP target 0xffffffff8b0b92e0; Evidence ev_82acdf71e9e6899e004a426a2141a8776e856f82f6bf71e75144b2de76a05261 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0b92e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0b92e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x850, VA 0xffffffff8ac25fb0, JMP target 0xffffffff8adf4da0; Evidence ev_5761db143391b671ba6ab7b241cd61409b0afc0f64ddc42c3cfc9d3be6d428be */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf4da0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adf4da0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x858, VA 0xffffffff8ac25fb8, JMP target 0xffffffff8adf4db0; Evidence ev_cfa0f745d5ebb5a86a7e3b4d3a314cc7ad8fb83a1002f076ab6020b179c0429d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf4db0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adf4db0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x860, VA 0xffffffff8ac25fc0, JMP target 0xffffffff8adf4dc0; Evidence ev_7502b5e534b2cbb3589cb1756906ac5cecd468bebe20c3f2f64a5010da899ebc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf4dc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adf4dc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x868, VA 0xffffffff8ac25fc8, JMP target 0xffffffff8adf7d90; Evidence ev_0f93f89c2d9636281c837dd8daacb79a986b0a485f3da15ae24565b86a59bf07 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf7d90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8adf7d90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x870, VA 0xffffffff8ac25fd0, JMP target 0xffffffff8adf8280; Evidence ev_5d4292882b75cc78743d7ec2208f60678f75a6188690be2329c50b3692ddda8a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8adf8280); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_438280(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  undefined8 uStack_40;
  undefined8 uStack_38;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  if (param_2[6] != 0) {
    iVar2 = func_0xffffffff8ac19720(param_2[6],(long)*(int *)(param_1 + 0x9c));
    uVar3 = 0xe;
    if (iVar2 != 0) goto LAB_ffffffff8adf83a1;
  }
  if (param_2[7] != 0) {
    iVar2 = func_0xffffffff8ac19720(param_2[7],(long)*(int *)(param_1 + 0x9c));
    uVar3 = 0xe;
    if (iVar2 != 0) goto LAB_ffffffff8adf83a1;
  }
  uStack_40 = param_2[2];
  uStack_38 = param_2[3];
  if ((*(byte *)(param_2 + 8) & 4) != 0) {
    *(byte *)(param_1 + 0xed) = *(byte *)(param_1 + 0xed) | 0x80;
  }
  *(undefined8 *)(param_1 + 0x4f0) = 0;
  *(undefined8 *)(param_1 + 0x550) = 0;
  *(undefined8 *)(param_1 + 0x5b0) = 0;
  *(undefined8 *)(param_1 + 0x5b8) = 0;
  *(undefined8 *)(param_1 + 0x5c0) = 0;
  *(undefined8 *)(param_1 + 0x5c8) = 0;
  *(undefined8 *)(param_1 + 0x598) = 0;
  *(undefined8 *)(param_1 + 0x5d0) = 0;
  func_0xffffffff8b4111f0(param_1,*param_2,param_2[1],&uStack_40);
  uVar3 = func_0xffffffff8b411300(param_1,param_2[4]);
  if ((int)uVar3 == 0) {
    iVar2 = func_0xffffffff8b4c78d0();
    uVar3 = 0;
    if (iVar2 != 0) {
      func_0xffffffff8aa659e0(param_1,param_2[2],param_2[3]);
      uVar3 = 0;
    }
  }
LAB_ffffffff8adf83a1:
  if (_DAT_ffffffff8e2dc310 == lStack_28) {
    return uVar3;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0x878, VA 0xffffffff8ac25fd8, JMP target 0xffffffff8b4a6690; Evidence ev_345480c50df82accfe6997c5ba3c93cc6288b477cb0d38855234ef032aabcb76 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4a6690); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4a6690(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x880, VA 0xffffffff8ac25fe0, JMP target 0xffffffff8b4a6580; Evidence ev_74f4b185649f54504c0e0913aa8eee2b6657f2c9244213e21d0c7fc905a6ca8f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4a6580); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4a6580(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x888, VA 0xffffffff8ac25fe8, JMP target 0xffffffff8ae090d0; Evidence ev_aea86123378b448ee5adb4635ba3537513173d1d296db4958eea7bf9167c6123 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae090d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae090d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x890, VA 0xffffffff8ac25ff0, JMP target 0xffffffff8aa66dc0; Evidence ev_e80e7a1f6ba99566b3948e67368dd3a40ca97f030fb98ac21c4c322e730c3783 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa66dc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa66dc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x898, VA 0xffffffff8ac25ff8, JMP target 0xffffffff8ae0aa70; Evidence ev_de1cd106387bbacf81297081f7785122464fc773d16754ed603ff008843021af */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae0aa70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae0aa70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8a0, VA 0xffffffff8ac26000, JMP target 0xffffffff8b376110; Evidence ev_e7768edda17e5f94003e797fe77d9ff6a6d3196ffe84d79ee64e6641c5909986 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b376110); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b376110(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8a8, VA 0xffffffff8ac26008, JMP target 0xffffffff8aa67670; Evidence ev_a422267068a4c10eedc2e7fa946331f07d472c95764b98bd8d75d9f4775978a7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa67670); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa67670(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8b0, VA 0xffffffff8ac26010, JMP target 0xffffffff8aa67850; Evidence ev_8d305b98475b7b985c62808bf0d5fb90d11c0e6e3dfc8e3f293e5410b72ec9e4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa67850); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa67850(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8b8, VA 0xffffffff8ac26018, JMP target 0xffffffff8aa67880; Evidence ev_1104d932b91ccb11d405abad1970915223d066ff2c277d1d00cf44e30d7f9add */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa67880); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa67880(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8c0, VA 0xffffffff8ac26020, JMP target 0xffffffff8ae12040; Evidence ev_33a72aca933f12546a9a13c9578b72fe6dc057014c0c8d9691816c82a46364f4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae12040); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae12040(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8c8, VA 0xffffffff8ac26028, JMP target 0xffffffff8ae14cc0; Evidence ev_b89cb75715584c50918070896305e6076d819c61965ba98950a81e934d53fd86 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae14cc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae14cc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8d0, VA 0xffffffff8ac26030, JMP target 0xffffffff8ae17820; Evidence ev_ac60b4edb77df0cf766945c7c98f7ab87da17774bf62364c63a00e070da07c53 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae17820); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae17820(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8d8, VA 0xffffffff8ac26038, JMP target 0xffffffff8ae2df70; Evidence ev_c204a5a89d587f8a449e183f2ea9415de9bd1f522828ea9a983d6688908bdfb3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae2df70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae2df70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8e0, VA 0xffffffff8ac26040, JMP target 0xffffffff8ae2e080; Evidence ev_7f5a81de5386a414c136d761b444f09147d692621cbe1fffb7de77663e01955a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae2e080); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae2e080(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8e8, VA 0xffffffff8ac26048, JMP target 0xffffffff8ae32990; Evidence ev_93c6d7eb70c2c45bd13e9e6c872cd234e807b6f8e87612cd1fecc265dd5098a2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae32990); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae32990(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8f0, VA 0xffffffff8ac26050, JMP target 0xffffffff8ae333b0; Evidence ev_11b99e35b16404cc162ccd2684098e85b189f119c31d51e51b88ed27e9afafd8 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae333b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae333b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x8f8, VA 0xffffffff8ac26058, JMP target 0xffffffff8ae338b0; Evidence ev_0137fdc126f15fe551d7008aa16d1df1926868a21683718a6bbdeb6114c354f7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae338b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae338b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x900, VA 0xffffffff8ac26060, JMP target 0xffffffff8ae34250; Evidence ev_6f5634f26eefda915776c3402fcfcb16e83143b6f237d0ca98a814eb7e172658 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae34250); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae34250(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x908, VA 0xffffffff8ac26068, JMP target 0xffffffff8ae34db0; Evidence ev_abb7e8a34cdd190a57825c2f47e62c18f32a48ba9c1cdb9f1478f0412969fdef */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae34db0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae34db0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x910, VA 0xffffffff8ac26070, JMP target 0xffffffff8ae3cff0; Evidence ev_a002ef2f50cb75f5d681d0428920dd2cb3b7e3a956f3231f6f59ca01ee1124a3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae3cff0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae3cff0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x918, VA 0xffffffff8ac26078, JMP target 0xffffffff8abddff0; Evidence ev_87975ab5ec25c723c158f862271e9ed9f9c033c69d595518cdec9d1a6dc2e3e9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8abddff0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8abddff0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x920, VA 0xffffffff8ac26080, JMP target 0xffffffff8ae50300; Evidence ev_d7f8e8114938242bd66daaba865e8293f61649a84e5483c16fe1c999e38c41bb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae50300); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae50300(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x928, VA 0xffffffff8ac26088, JMP target 0xffffffff8ae50db0; Evidence ev_be0370ff4227574b166db649fcdea76cf6a7f8b29634d5cdcdca0c4fd7246b56 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae50db0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae50db0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x930, VA 0xffffffff8ac26090, JMP target 0xffffffff8ae57fb0; Evidence ev_4099bb659c6297992cc7f698f8308fed393d195e9a72d738078e7d525819296b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae57fb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae57fb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x938, VA 0xffffffff8ac26098, JMP target 0xffffffff8ae57fe0; Evidence ev_5d43e3355d85ba6e815a09c8398d588324d410206ca92ed3c889c67313dd5d1f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae57fe0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae57fe0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x940, VA 0xffffffff8ac260a0, JMP target 0xffffffff8ae58630; Evidence ev_ae9b3a06170e6eb638d9f8de7866b261ea1c87fc644a7770657fceb8f5b51804 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae58630); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae58630(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x948, VA 0xffffffff8ac260a8, JMP target 0xffffffff8ae58640; Evidence ev_a2204c190764d2e6ea10cc45554289a78ebed04098bac1ba685c9e9abb1cc5f7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae58640); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae58640(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x950, VA 0xffffffff8ac260b0, JMP target 0xffffffff8b2b7bc0; Evidence ev_c004ed395f146ce95de524dfd2899a658986391bd13cee3000a1a80b997fd90a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b7bc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b7bc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x958, VA 0xffffffff8ac260b8, JMP target 0xffffffff8b2b6800; Evidence ev_f3767ae57f5a48c06be41c7591814bcdd086204c342351a7cd0ebf6f382a0766 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b6800); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b6800(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x960, VA 0xffffffff8ac260c0, JMP target 0xffffffff8b2b7420; Evidence ev_112b35961635e07b92ae94f3af096629c7c29afb4ae1e3436a7309dd80eb4e0a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b7420); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b7420(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x968, VA 0xffffffff8ac260c8, JMP target 0xffffffff8b2b9f80; Evidence ev_3647f81d26e724d9e71ed49a557d0bbcddec73885cdfe1562af462bee6e93f74 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9f80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9f80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x970, VA 0xffffffff8ac260d0, JMP target 0xffffffff8af9f350; Evidence ev_933a6799bbf419ba92d0adc8450efc719630277816ce14b05348d52a0d449488 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af9f350); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af9f350(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x978, VA 0xffffffff8ac260d8, JMP target 0xffffffff8af9f820; Evidence ev_5c16bcc394b1b03438c4796d83d79fb8c4cf2b7ae44e923df7b917100dc2085c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af9f820); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af9f820(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x980, VA 0xffffffff8ac260e0, JMP target 0xffffffff8b3f4ce0; Evidence ev_4d6b4c1a5eb9891949b4679bcea824be6f2863a2bae9793117a053ee2c7a6e14 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3f4ce0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3f4ce0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x988, VA 0xffffffff8ac260e8, JMP target 0xffffffff8afa84a0; Evidence ev_eaf8b36632130452c296371f9dd831cab82d21edd9c1288cab16c033bbd4d171 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afa84a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afa84a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x990, VA 0xffffffff8ac260f0, JMP target 0xffffffff8b2b81f0; Evidence ev_054905ef143786b9fd3b24db0be49d1bfbce38d5737f7c1835c37f3f824a33da */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b81f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b81f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x998, VA 0xffffffff8ac260f8, JMP target 0xffffffff8b2b9410; Evidence ev_d84e121fdaf2a040b5f46418eef7a7eea43f7533ffc7797dd854e0936c4f1afb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9410); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9410(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9a0, VA 0xffffffff8ac26100, JMP target 0xffffffff8b2bc3f0; Evidence ev_f7d4dc446ce0f0a19e84ad6690cdc1ae8767d0b8b448946efe221e7e15a71674 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bc3f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bc3f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9a8, VA 0xffffffff8ac26108, JMP target 0xffffffff8b2b6c90; Evidence ev_16863397b697fc007b495937a270fc990f7ece38fea2b8e260cea8d37d21ccc0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b6c90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b6c90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9b0, VA 0xffffffff8ac26110, JMP target 0xffffffff8b671a10; Evidence ev_d67521a6a6535348768673f4f99c1f9de5864fa7933618dd42b32eef0241220a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b671a10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b671a10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9b8, VA 0xffffffff8ac26118, JMP target 0xffffffff8b4783a0; Evidence ev_e5d0a874029910e8057d8df7e4663d6479784ce142f271ecf7892386153f2a08 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4783a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4783a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9c0, VA 0xffffffff8ac26120, JMP target 0xffffffff8b4783b0; Evidence ev_c5d44d482c7dfeb430e4a65148172b8c26e5545978500773890559a034a4e2e7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4783b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4783b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9c8, VA 0xffffffff8ac26128, JMP target 0xffffffff8b2ba1c0; Evidence ev_5a618de85ec75ca14a7e534651ea6b085861eee7842aec8b30bc227b1b25b393 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2ba1c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2ba1c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9d0, VA 0xffffffff8ac26130, JMP target 0xffffffff8b2b7b40; Evidence ev_debe14baf768c0da433a7c8e6c822224faf8b58012da6ed46e2e64a6cbe07055 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b7b40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b7b40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9d8, VA 0xffffffff8ac26138, JMP target 0xffffffff8ae60960; Evidence ev_7fc3cad42bb54333a189b6a90f6cb2bc9f177786ef55043440203579343d0019 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae60960); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae60960(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9e0, VA 0xffffffff8ac26140, JMP target 0xffffffff8b0e9780; Evidence ev_1d3d7e7dcce01b345dca9480042628f7c03d49efcb8666558d35f1c857f4705e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0e9780); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0e9780(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9e8, VA 0xffffffff8ac26148, JMP target 0xffffffff8b0e9790; Evidence ev_befefda6ba4528382755e49532aebfb92404d8c359d10d4d84c5410ddb0ecfff */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0e9790); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0e9790(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9f0, VA 0xffffffff8ac26150, JMP target 0xffffffff8b0e97a0; Evidence ev_397487bf3e8420bb7b17a78b75db5f71ebc3615b9289fde8033b796a5b6a13ef */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0e97a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0e97a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0x9f8, VA 0xffffffff8ac26158, JMP target 0xffffffff8b07b590; Evidence ev_f6f25779f23992ea580dceaffa40af9e5d5b37505584614e51de35b6560df157 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b07b590); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b07b590(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa00, VA 0xffffffff8ac26160, JMP target 0xffffffff8b478da0; Evidence ev_607cacf4864cb52df5c70776c16432f8e0602a33c7ffb008a89c8c1176bb88ae */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b478da0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b478da0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa08, VA 0xffffffff8ac26168, JMP target 0xffffffff8b2ba170; Evidence ev_3a00c8fdd0f4b9896f45769d16253314e5b8a04f99af542433a5d459d4ff4a9d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2ba170); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2ba170(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa10, VA 0xffffffff8ac26170, JMP target 0xffffffff8b53f0c0; Evidence ev_e5f86ec02cd93c158e63e3fd158f8689f9bd616ebe49b0270089c9032b44c010 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53f0c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53f0c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa18, VA 0xffffffff8ac26178, JMP target 0xffffffff8b53f100; Evidence ev_377f5e1320f3d530adbecf4c51ac6bceb3c4b95f49164df71bce281ebb04e4ab */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53f100); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53f100(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa20, VA 0xffffffff8ac26180, JMP target 0xffffffff8b2b9cf0; Evidence ev_2da4191bc20c9ef1e9c9117355e71e7c912f1a0b06e8b29b6dd425fd2eeaf8a1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9cf0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9cf0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa28, VA 0xffffffff8ac26188, JMP target 0xffffffff8b2ba740; Evidence ev_e4bfb93a2a6ea5e0e397ab7388b1f223aface7451b487f02413aea2b69a29384 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2ba740); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2ba740(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa30, VA 0xffffffff8ac26190, JMP target 0xffffffff8af12b70; Evidence ev_38404cb6753f15a3579cc328e790d4632a35afd20208c8e283cef25d08aa584b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12b70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12b70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa38, VA 0xffffffff8ac26198, JMP target 0xffffffff8af12bf0; Evidence ev_b0e7f0e651de029b075f919bdb07eaaaeb1962c4a7b66d3891631dd685b3cd9e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12bf0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12bf0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa40, VA 0xffffffff8ac261a0, JMP target 0xffffffff8af12c50; Evidence ev_37dcb2e4b55f0f75397c3f0f1217effd98edb76223fd39fcc8df5d1f79ba4226 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12c50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12c50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa48, VA 0xffffffff8ac261a8, JMP target 0xffffffff8af12c80; Evidence ev_6661c8277dd71a46a0d3cc61a3057109b5c469ad295a4a1f7cce2f330384dd24 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12c80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12c80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa50, VA 0xffffffff8ac261b0, JMP target 0xffffffff8af12cb0; Evidence ev_9ec0a872163921a61559750d4bd60418206624d6f107047ebdca96a5da77b075 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12cb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12cb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa58, VA 0xffffffff8ac261b8, JMP target 0xffffffff8af12ce0; Evidence ev_95ba4c5d64a5fb4287f3f471722b70fece34278aecb89fd0b16829819902b5d7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12ce0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12ce0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa60, VA 0xffffffff8ac261c0, JMP target 0xffffffff8b53e800; Evidence ev_1e64498678e196df2052363234bc0e4edf903f7c2a1b93dc7d99207aeb738aed */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53e800); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53e800(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa68, VA 0xffffffff8ac261c8, JMP target 0xffffffff8b53ebe0; Evidence ev_884786577e215161ce3b239d9ab6a4711cb4d56a69b6658bb56731a6086551b3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53ebe0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53ebe0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa70, VA 0xffffffff8ac261d0, JMP target 0xffffffff8b53ef70; Evidence ev_2b68ee165d495f111f02bf427dfdaffe08c7a136a03c3770bd427d5892a201b1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53ef70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53ef70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa78, VA 0xffffffff8ac261d8, JMP target 0xffffffff8b5c6d30; Evidence ev_70407a417188d610f07cc250d6bf7bd16ae3a803d9a982c9c2e1f0e161c90341 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5c6d30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5c6d30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa80, VA 0xffffffff8ac261e0, JMP target 0xffffffff8b152690; Evidence ev_3519f17dde67bea665b1a0d36b3dc205f389329528fcfac480a72e974995a00e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b152690); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b152690(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa88, VA 0xffffffff8ac261e8, JMP target 0xffffffff8afa8b20; Evidence ev_561b181cdbbe0da842ee4c61d2445f72e3f8cba61d61cc3778d1a5ccd3fd75ab */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afa8b20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afa8b20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa90, VA 0xffffffff8ac261f0, JMP target 0xffffffff8af12d10; Evidence ev_cc566ddb32757dfbb8b5a633570c3d00995b25d31d8d38d5532cbea441da3a34 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af12d10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af12d10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xa98, VA 0xffffffff8ac261f8, JMP target 0xffffffff8b53f160; Evidence ev_b91b2b81f5acdd4ff82d3d01ea2d34e2bf906d91b12c17596ec29ee8c5681a2c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53f160); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53f160(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xaa0, VA 0xffffffff8ac26200, JMP target 0xffffffff8af9e250; Evidence ev_462fbaafe26f4b4cdd944a00b302eb61992dd4244a55fa96d7094252dc358c6e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af9e250); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af9e250(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xaa8, VA 0xffffffff8ac26208, JMP target 0xffffffff8b414a30; Evidence ev_8aea0ca2edb36dc33d537ce47fcb22757e36d9550b92a8870e441050d9758a70 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xab0, VA 0xffffffff8ac26210, JMP target 0xffffffff8b414a40; Evidence ev_604fc366acec3ca6b3842c63c496b84c7ce1aeffbae23111f2957acf97b4193e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xab8, VA 0xffffffff8ac26218, JMP target 0xffffffff8b414a50; Evidence ev_36b45c4f53fe9653f07bc2b551cf6481fb98b3602a5fe35cedced2c764850317 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xac0, VA 0xffffffff8ac26220, JMP target 0xffffffff8b414a60; Evidence ev_75d19ac7892e72bbdbbf3aafc376736dbfb60ec43d1ea462df45d6a9aac4eeb4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xac8, VA 0xffffffff8ac26228, JMP target 0xffffffff8b414a80; Evidence ev_dcf56db5e865730caac7118122b73a384d2b0ca50d655ed69036969d429e88f4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xad0, VA 0xffffffff8ac26230, JMP target 0xffffffff8b414a90; Evidence ev_2c4e3bed8847899981b949390d47fffc36ef214b202459f85553b61d02e84f70 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xad8, VA 0xffffffff8ac26238, JMP target 0xffffffff8b2b9720; Evidence ev_387d259d720725905cef732c2db37b7b96bcaf2e2a3c9e479b83e102f2ee6465 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9720); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9720(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xae0, VA 0xffffffff8ac26240, JMP target 0xffffffff8b414ab0; Evidence ev_96b94c16e5dcc762347c995049c3f2ba26bd1501ec7074b39c0dc32622fcc5a0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414ab0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414ab0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xae8, VA 0xffffffff8ac26248, JMP target 0xffffffff8b2b64e0; Evidence ev_396510e34fa5273bdb2fe8c6d2a4f4115e09635c0a670f71de53664e2d6a6113 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b64e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b64e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xaf0, VA 0xffffffff8ac26250, JMP target 0xffffffff8b2b5ef0; Evidence ev_b476d9058899a793358f2d042f92e38b7585061695579bdc6f5bd822221f6595 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b5ef0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b5ef0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xaf8, VA 0xffffffff8ac26258, JMP target 0xffffffff8b414a20; Evidence ev_13ef6f94e9f61cd66948ea0cceb6c6dc71f2f5d0f784a393c47a1c47b25ee18a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb00, VA 0xffffffff8ac26260, JMP target 0xffffffff8b414a70; Evidence ev_4f911349c43a38b3ddf4058d8fd861cdccac43a751d7a380bf23a2e2fc647e18 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414a70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414a70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb08, VA 0xffffffff8ac26268, JMP target 0xffffffff8b414aa0; Evidence ev_54e2666cdd4855702dc8f5ea529450453935839f6682e9e5f6ff5247572df310 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b414aa0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b414aa0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb10, VA 0xffffffff8ac26270, JMP target 0xffffffff8b0a54d0; Evidence ev_f6121e5286f207388220489f88cfee231bfd40a03f04b3ab2c180b75a4caf3ad */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0a54d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0a54d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb18, VA 0xffffffff8ac26278, JMP target 0xffffffff8b53f4b0; Evidence ev_108a40c4af5ef9f02a85fb5d3ed0e12b24598f53b61cefa0de51917cc16455ea */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53f4b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53f4b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb20, VA 0xffffffff8ac26280, JMP target 0xffffffff8b1fd660; Evidence ev_a964ccfe3184d0ae5e84eedc7b635a378444c01f5d0af19e0152390915f3e457 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1fd660); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1fd660(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb28, VA 0xffffffff8ac26288, JMP target 0xffffffff8b1fd7c0; Evidence ev_febe219384fb62f3660032b3a8f3121b2bd319cbf16b3961078a9ba1fe0374dc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1fd7c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1fd7c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb30, VA 0xffffffff8ac26290, JMP target 0xffffffff8b1fdab0; Evidence ev_69f2dd68202dcade90d1430b3334d41aab9b2185ab50230320f9588ca58a980e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1fdab0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1fdab0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb38, VA 0xffffffff8ac26298, JMP target 0xffffffff8b1fde80; Evidence ev_3d5fe35786917e6f0a931f43ca989f841a00ee34617a706ba8455d0d686f9cf7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1fde80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1fde80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb40, VA 0xffffffff8ac262a0, JMP target 0xffffffff8b2b9c80; Evidence ev_ad882f618471a7df9c4d93c6d5b73573d0a49dd39c27f568c9d5fb8db40d6cbb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b9c80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b9c80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb48, VA 0xffffffff8ac262a8, JMP target 0xffffffff8b2ba110; Evidence ev_20c5f9f1976e3f0fd24f456e02fc4b3ba4f4ed70908151b427d86aa3d4d0372b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2ba110); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2ba110(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb50, VA 0xffffffff8ac262b0, JMP target 0xffffffff8b2b91b0; Evidence ev_53b542deccf6f4247b3aec5ccaad29927918a6d7de8f0280ed46df03670d89b7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b91b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b91b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb58, VA 0xffffffff8ac262b8, JMP target 0xffffffff8b2ba4f0; Evidence ev_a35fda9a442eda8e385ee0f2b6cfdc659319cc5cf5e7fecf8b864e533a4bebbf */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2ba4f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2ba4f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb60, VA 0xffffffff8ac262c0, JMP target 0xffffffff8b2b8090; Evidence ev_f20997a8f4a01cdf2fe59266c4f14a36c514f2e59bf9e6d2744195cf95907706 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b8090); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b8090(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb68, VA 0xffffffff8ac262c8, JMP target 0xffffffff8b2bbb80; Evidence ev_bcdddb92311ad93d4f8c09aa7af3812f4f7a5003961f976521bab13cdf080e6b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bbb80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bbb80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb70, VA 0xffffffff8ac262d0, JMP target 0xffffffff8b2b7b80; Evidence ev_93a265d42808f7c9b57ccbfa0a8b02deabc48f8adf060fb46f7714c9f8d21a34 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b7b80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b7b80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb78, VA 0xffffffff8ac262d8, JMP target 0xffffffff8b2b7890; Evidence ev_a23eddeaaee22065e579a8e23ba2eea14866f2cf4f5be646c150f59b6941be7f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b7890); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b7890(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb80, VA 0xffffffff8ac262e0, JMP target 0xffffffff8b2bb8a0; Evidence ev_a52c2e8377fd1facc90e3077b10c4bb2f0e05e4a4411210ac994b76c2eaeeb18 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bb8a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bb8a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb88, VA 0xffffffff8ac262e8, JMP target 0xffffffff8b2b8510; Evidence ev_fda4df19fd4d2b38bee1759fc2a9e3adb5a412a4f46d5e03414c9c6e308f77f4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b8510); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b8510(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb90, VA 0xffffffff8ac262f0, JMP target 0xffffffff8b2b8800; Evidence ev_b4695e730b201226d20c6c5c9bd4542371c2b8f022e02f1054391d22ef42382f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b8800); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b8800(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xb98, VA 0xffffffff8ac262f8, JMP target 0xffffffff8ae5b080; Evidence ev_0f790fe88934928cf899e0fb523e7b26d8a512039de821fd6f02f1d52000b2e0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b080); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b080(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xba0, VA 0xffffffff8ac26300, JMP target 0xffffffff8ae5b090; Evidence ev_5e2b07f7d1e828440f1ea1f6e42bde95229d3b8ac616333e95cbe1312d354504 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b090); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b090(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xba8, VA 0xffffffff8ac26308, JMP target 0xffffffff8af1fa50; Evidence ev_0e22ead61a75b051693da4931bd6ce2993ef589b8ac631e033083e6db4941bd5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1fa50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1fa50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbb0, VA 0xffffffff8ac26310, JMP target 0xffffffff8b5f4870; Evidence ev_9d575e8fb66b0a9ce932ff6005628cdfc270810815e61ab702f162686afc01ec */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5f4870); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5f4870(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbb8, VA 0xffffffff8ac26318, JMP target 0xffffffff8b19ccf0; Evidence ev_0e7cadf92faf9878eb2b15efb64ff0bb9909ddcf5d78c246aaafe3bdbba17384 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b19ccf0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b19ccf0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbc0, VA 0xffffffff8ac26320, JMP target 0xffffffff8b19cd00; Evidence ev_1cb6751a485b057e3a4bda64bd6045cd9a2e754079583804213ff16f5339b8fa */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b19cd00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b19cd00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbc8, VA 0xffffffff8ac26328, JMP target 0xffffffff8b19cd10; Evidence ev_58405d0c3bfc385c957b555464f72e604c170eefc0bb681f9020f3feb29d789c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b19cd10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b19cd10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbd0, VA 0xffffffff8ac26330, JMP target 0xffffffff8b19cd20; Evidence ev_4faa7b7044649918f0be4beb682ce143e07946c28ff6258926382ba0a0ddbe39 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b19cd20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b19cd20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbd8, VA 0xffffffff8ac26338, JMP target 0xffffffff8b19cd30; Evidence ev_b3228fa55f23c163d2dbf05f3feb08b17e080b71a7d3bf934221289d2070d843 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b19cd30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b19cd30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbe0, VA 0xffffffff8ac26340, JMP target 0xffffffff8af66c90; Evidence ev_7272472501b8b5c4db3debfb27df093835eefbed9978d82fcccff0887381cc0c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af66c90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af66c90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbe8, VA 0xffffffff8ac26348, JMP target 0xffffffff8af67300; Evidence ev_6a03f60456a1282e14cd61dfcaab27631aedb1a2d89491193faaa6a58392c05e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af67300); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af67300(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbf0, VA 0xffffffff8ac26350, JMP target 0xffffffff8af67610; Evidence ev_b0d067a361f6184ff743716842dc908171251b898bf543a6d23843dd5ba0cd30 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af67610); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af67610(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xbf8, VA 0xffffffff8ac26358, JMP target 0xffffffff8af67900; Evidence ev_458f957bb9e193dd94d08406cd9a99b2c6b95c5ff905ea4516aa43438e6da99f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af67900); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af67900(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc00, VA 0xffffffff8ac26360, JMP target 0xffffffff8b65c830; Evidence ev_56bd8b5be57ec33bae969d2f52c7919fdd2c20608938ecfcbe505b85d17ce265 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b65c830); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b65c830(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc08, VA 0xffffffff8ac26368, JMP target 0xffffffff8af67f00; Evidence ev_8bf79f674d107bda371cfda72f93aa7e08e369b5aa962e0b680552c7079c452d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af67f00); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af67f00(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc10, VA 0xffffffff8ac26370, JMP target 0xffffffff8af68070; Evidence ev_b17db34514e892e8f555ebb056c556b16102e39c18e5658c95a00b7bd06910a5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af68070); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af68070(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc18, VA 0xffffffff8ac26378, JMP target 0xffffffff8b5a8480; Evidence ev_0185cee840c5bcacdf9f88cdebcac2d93be3a14f404b0188ad3d911a5fb65dba */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b5a8480); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b5a8480(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc20, VA 0xffffffff8ac26380, JMP target 0xffffffff8ae5b0a0; Evidence ev_a4c6f56095cbec4da7606171d68fb16dae48ce417b97836c929a0e680e2919db */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b0a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b0a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc28, VA 0xffffffff8ac26388, JMP target 0xffffffff8ae5b0c0; Evidence ev_25a15f6133baec4769d1aa928f63fb538d1ba71e71848cfdee706e26ae006010 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b0c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b0c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc30, VA 0xffffffff8ac26390, JMP target 0xffffffff8ae5b0d0; Evidence ev_3b41b316d92bd07a3380d266065a811bac7c2ff9dfd685201e88ea43e8939f29 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b0d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b0d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc38, VA 0xffffffff8ac26398, JMP target 0xffffffff8ae5b0e0; Evidence ev_4f3f8ff54a11a8dd5fc80af797c2f8e40085bd740a36a5939e36a77a807c9d66 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b0e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b0e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc40, VA 0xffffffff8ac263a0, JMP target 0xffffffff8ae5b0f0; Evidence ev_8df25225280002610ee095228b6f0e4cab16eebae64070629350608c605591f3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5b0f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5b0f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc48, VA 0xffffffff8ac263a8, JMP target 0xffffffff8aef0720; Evidence ev_236b1fb36ce531949382ab15c4419efab6cfda3f306acfb1ea53f044a632432c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef0720); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef0720(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc50, VA 0xffffffff8ac263b0, JMP target 0xffffffff8aef1670; Evidence ev_de300636b5c3c87f00bce6b55b39054a830546d2cc741cf1035b94f4c2765860 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef1670); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef1670(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc58, VA 0xffffffff8ac263b8, JMP target 0xffffffff8b2b96f0; Evidence ev_a930fe842df74b8d51df41ac849dd4649c3895c626d97deac9cc17efc238ede2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b96f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b96f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc60, VA 0xffffffff8ac263c0, JMP target 0xffffffff8aef1230; Evidence ev_d33e0ccf1129371819aa4ee472b6b81521f370a311e67ca1cd288167d6686438 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef1230); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef1230(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc68, VA 0xffffffff8ac263c8, JMP target 0xffffffff8b1c2df0; Evidence ev_9476872c80a5b326b221feec237f38f816c8ac0862f6a31d8f394b0f0aaf733a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1c2df0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1c2df0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc70, VA 0xffffffff8ac263d0, JMP target 0xffffffff8b53f140; Evidence ev_93c91617656444b7b5ba65759becc2131001c0a17c9cc2bb21ad792a08d481aa */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b53f140); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b53f140(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc78, VA 0xffffffff8ac263d8, JMP target 0xffffffff8b4a35e0; Evidence ev_95cb7b15b857deb7b35e34a6ab8d6e38894eff05c351861e05c3471aaf9a9f19 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4a35e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4a35e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc80, VA 0xffffffff8ac263e0, JMP target 0xffffffff8aeaee20; Evidence ev_5977a879f76a68348fa16855f08a901ca531f003aaf7a104b22b34a03d8a912d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeaee20); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeaee20(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc88, VA 0xffffffff8ac263e8, JMP target 0xffffffff8b2bab10; Evidence ev_e4dc9921e1e679ee76488bbf11e0129604650a4a3add9753e668da38d1c72714 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bab10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bab10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc90, VA 0xffffffff8ac263f0, JMP target 0xffffffff8b2bae30; Evidence ev_77fec82670d8c7adfb8a5d387b5854fa3cef17db77b0a832f07516fd6b6a6509 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2bae30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2bae30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xc98, VA 0xffffffff8ac263f8, JMP target 0xffffffff8b389220; Evidence ev_8574797d3713753437ebefd8004f6f8c9b58160782f968ed0ced7444d710308f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b389220); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b389220(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xca0, VA 0xffffffff8ac26400, JMP target 0xffffffff8b389100; Evidence ev_ace47fc4b090bd9f2e056e1001c36437cd023d61d685b5c25db2d01c20209a38 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b389100); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b389100(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xca8, VA 0xffffffff8ac26408, JMP target 0xffffffff8b002310; Evidence ev_4c657d915a3676e7cb275eafeec1d55a7c29666ed7d7a6a07aeb8bf56cbfe611 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b002310); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b002310(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcb0, VA 0xffffffff8ac26410, JMP target 0xffffffff8b002820; Evidence ev_b54a3b91c9bbbb2493cfd8e468d3e73bbc50f059db40527fe1534de56162be67 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b002820); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b002820(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcb8, VA 0xffffffff8ac26418, JMP target 0xffffffff8b0036e0; Evidence ev_1627360834da58937cc0443783aabc45750c6c26f41b5d3787f87b6d3381be36 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0036e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0036e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcc0, VA 0xffffffff8ac26420, JMP target 0xffffffff8b0038d0; Evidence ev_04f235402bc16520591888a01b64703a1db879c511b00ef801a6c933af7a17d5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0038d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0038d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcc8, VA 0xffffffff8ac26428, JMP target 0xffffffff8b003c60; Evidence ev_98822d5b081012710a784b47e26a47f70850ea4cf23d9457c604f66d1dcd934f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b003c60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b003c60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcd0, VA 0xffffffff8ac26430, JMP target 0xffffffff8b3b8290; Evidence ev_b8f5801223fcad0a843082373b3a4395c5bebe43d0e524c851ef165d17ff2e40 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3b8290); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3b8290(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcd8, VA 0xffffffff8ac26438, JMP target 0xffffffff8b3bbb70; Evidence ev_7f157bf62c5b17d5846b5708f7d0cccda34bcedb31d957aba989ca357dc3de20 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bbb70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bbb70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xce0, VA 0xffffffff8ac26440, JMP target 0xffffffff8b405280; Evidence ev_cac0caa1ab22a74142c1a9408eda5d48e94a510fb65c33cf1ef3e77f29ca4768 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b405280); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b405280(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xce8, VA 0xffffffff8ac26448, JMP target 0xffffffff8b647ca0; Evidence ev_133f074fdac470fc0ab793bb433534f2590cdfcb308158f7a9be0208c4be7559 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b647ca0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b647ca0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcf0, VA 0xffffffff8ac26450, JMP target 0xffffffff8b3bf000; Evidence ev_b4e694c12847308c8cca0dd1dc485cb6ad7686f7d17a8b615ec7238e303fda2c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bf000); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bf000(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xcf8, VA 0xffffffff8ac26458, JMP target 0xffffffff8b3c0780; Evidence ev_da6e79b574afbcf3aac9f804d4fd901c0780ca7efcd17db4052864f779e0a1d5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3c0780); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3c0780(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd00, VA 0xffffffff8ac26460, JMP target 0xffffffff8b3c07e0; Evidence ev_6228159e85d07a6d61a9a0f921a75ff43753ea40d37601470afcbc49c1bb9bf2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3c07e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3c07e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd08, VA 0xffffffff8ac26468, JMP target 0xffffffff8b47e830; Evidence ev_6da8db51c65723d573933414ba293a346ffbfb6fcad3229386bb507a68942472 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47e830); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abe830(long param_1,undefined8 *param_2)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  int iStack_2c;
  long lStack_28;
  
  lStack_28 = _DAT_ffffffff8e2dc310;
  iVar2 = func_0xffffffff8afc8f90(*(undefined8 *)(param_1 + 0x140));
  if (iVar2 == 0) {
    uVar3 = 1;
  }
  else {
    iStack_2c = 0;
    uVar3 = sub_abe260(param_1,*param_2,5,&iStack_2c);
    *(long *)(param_1 + 0x408) = (long)iStack_2c;
  }
  if (_DAT_ffffffff8e2dc310 == lStack_28) {
    return uVar3;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar1 = (code *)invalidInstructionException();
  (*pcVar1)();
}



/* Input +0xd10, VA 0xffffffff8ac26470, JMP target 0xffffffff8b3bcf30; Evidence ev_e5af7a2fd1af816a6ccba515febfa3ebc9e47f71a638b99f81b061327cbe1642 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bcf30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bcf30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd18, VA 0xffffffff8ac26478, JMP target 0xffffffff8afb0fc0; Evidence ev_c2c6ec17b41b70baecfec67c12e9a9aabb33ace74282c8516546c3756c7231f4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afb0fc0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afb0fc0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd20, VA 0xffffffff8ac26480, JMP target 0xffffffff8b2b73f0; Evidence ev_5740d90031260a2e842c3541c1bf7ed037d46b1bc6c7607f4ae2fadbd27fb830 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b2b73f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b2b73f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd28, VA 0xffffffff8ac26488, JMP target 0xffffffff8aeb7250; Evidence ev_fd92fa969f4acca217ea3ed4f849eda66ed2d430b835df6af4d4623345c428bc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeb7250); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeb7250(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd30, VA 0xffffffff8ac26490, JMP target 0xffffffff8b3bdad0; Evidence ev_20c5cdd10bb650acc5afa9f1b30a2d980e2f8ece5be18ee6f371bfa91c852dcb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bdad0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bdad0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd38, VA 0xffffffff8ac26498, JMP target 0xffffffff8b3bddb0; Evidence ev_b01910799fd53348d5505d9b12a5c86a5d3936eb91fbf7eba2f50ced2a53a941 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bddb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bddb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd40, VA 0xffffffff8ac264a0, JMP target 0xffffffff8b3bdf10; Evidence ev_58d9fff9168df3131e31c17e412318d4e7816c6a0bae30d5b333c9ea0c82d512 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bdf10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bdf10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd48, VA 0xffffffff8ac264a8, JMP target 0xffffffff8b0044d0; Evidence ev_2a7f1a0326eee2004329ef5320071e4b36caf10e5b7959fb3aaaf39e6cf21773 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0044d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0044d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd50, VA 0xffffffff8ac264b0, JMP target 0xffffffff8b010fd0; Evidence ev_1df2f47de9c3a7db92235d7af63d3b8ff4b924719b8b7623a35e86c3b93747c9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b010fd0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b010fd0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd58, VA 0xffffffff8ac264b8, JMP target 0xffffffff8b3bea30; Evidence ev_4cc53fab915f8077e727a903fa8918b7963637d73e5576240b38ff8ae039a2a0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3bea30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3bea30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd60, VA 0xffffffff8ac264c0, JMP target 0xffffffff8aeb7940; Evidence ev_e22678d981b48f42e954411199851093362eb70ee5ae49e6fdb2fde2bfca8013 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeb7940); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeb7940(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd68, VA 0xffffffff8ac264c8, JMP target 0xffffffff8b478ae0; Evidence ev_9c313a46a441798e2f0a379fe6d98b049616ede1ea41e393f02e8cd86ebc3eaf */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b478ae0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b478ae0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd70, VA 0xffffffff8ac264d0, JMP target 0xffffffff8b47b660; Evidence ev_c3b721557d90d4fc0357295def2739e6725a108c1f24caf7a1815ab5fcd215dc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47b660); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b47b660(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd78, VA 0xffffffff8ac264d8, JMP target 0xffffffff8b3be260; Evidence ev_a0e4e81f9c19149190830e06eec8a7e9287e8ad98c1edc464902ada1aa49f579 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3be260); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3be260(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd80, VA 0xffffffff8ac264e0, JMP target 0xffffffff8b3be4e0; Evidence ev_e7f43cc4f4954ca4468e66b0a801799e13f9c98e9323e60d84ffa966a97be76d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3be4e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3be4e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd88, VA 0xffffffff8ac264e8, JMP target 0xffffffff8b3be630; Evidence ev_0bcb736c8872d397307b0dc9648d122d08f90d02fc9ea6e58d8ba345ac3f539b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3be630); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3be630(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd90, VA 0xffffffff8ac264f0, JMP target 0xffffffff8b158330; Evidence ev_aa4e8fcc5014fdaede947ece69a27c6e3b2f444c40ec42253724f0b02b133e0f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b158330); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b158330(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xd98, VA 0xffffffff8ac264f8, JMP target 0xffffffff8b47d000; Evidence ev_349fefb262ea62c710accfcef40795c6e8f249ea1bbd3772eb3d888f940b6828 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b47d000); register/stack arguments unchanged. */

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 sub_abd000(undefined8 param_1,undefined4 *param_2)

{
  int iVar1;
  code *pcVar2;
  undefined8 uVar3;
  undefined8 *in_GS_OFFSET;
  undefined1 auStack_e0 [8];
  undefined1 auStack_d8 [168];
  long lStack_30;
  
  lStack_30 = _DAT_ffffffff8e2dc310;
  if ((param_2[2] == 10) || (uVar3 = 0x16, param_2[2] == 0)) {
    uVar3 = func_0xffffffff8b47ccc0(param_1,*param_2,auStack_e0);
    if ((int)uVar3 == 0) {
      iVar1 = param_2[2];
      uVar3 = *(undefined8 *)(param_2 + 4);
      func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
      uVar3 = func_0xffffffff8ac191d0(auStack_e0 + (long)iVar1 * 0x10,uVar3,8);
      if ((int)uVar3 == 0) {
        iVar1 = param_2[2];
        uVar3 = *(undefined8 *)(param_2 + 6);
        func_0xffffffff8b5da3e0(*in_GS_OFFSET,0xffffffff8bd0f297,0);
        uVar3 = func_0xffffffff8ac191d0(auStack_d8 + (long)iVar1 * 0x10,uVar3,8);
      }
    }
  }
  if (_DAT_ffffffff8e2dc310 == lStack_30) {
    return uVar3;
  }
  func_0xffffffff8b0bd6b0();
                    /* WARNING: Does not return */
  pcVar2 = (code *)invalidInstructionException();
  (*pcVar2)();
}



/* Input +0xda0, VA 0xffffffff8ac26500, JMP target 0xffffffff8aabc890; Evidence ev_4a4ed3812dad39569df1abaf5a009fadb5f3ccd8436c82c27365aea1fff26dd0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aabc890); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aabc890(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xda8, VA 0xffffffff8ac26508, JMP target 0xffffffff8ae5f090; Evidence ev_7800fa911d611e6bc89e076943d7091f71d050db5b772cb60731451eaaf03ec6 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5f090); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5f090(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdb0, VA 0xffffffff8ac26510, JMP target 0xffffffff8ae5f200; Evidence ev_a6cf3a1eae9a907e151d6a31fa978b62c9ca9d368e8fd9f304726e629455d27c */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae5f200); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae5f200(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdb8, VA 0xffffffff8ac26518, JMP target 0xffffffff8ae80590; Evidence ev_8c19b1afbc4242b21ff42f2d35c69976eaaded2e348b7a980bf529b48b2568aa */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae80590); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae80590(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdc0, VA 0xffffffff8ac26520, JMP target 0xffffffff8ae805b0; Evidence ev_926222c88438f55de067264484aaca97fb1d01b41d9eb4d8bf7d50992422c5fa */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae805b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae805b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdc8, VA 0xffffffff8ac26528, JMP target 0xffffffff8aa69430; Evidence ev_8795e8c30cc0d7e7b679db46989e58d3693c6fb87b79549368fcdea0a993b1b7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa69430); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa69430(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdd0, VA 0xffffffff8ac26530, JMP target 0xffffffff8ae8a350; Evidence ev_f5df9574f00b539b7d1aa4dc3f1c46fbb424092a56c82712bb0f60590b33013e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae8a350); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae8a350(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdd8, VA 0xffffffff8ac26538, JMP target 0xffffffff8ae8aa40; Evidence ev_7c7233a8a8a776ed52ddd265705b715351f3a9a6645f2e3e02ea63f57b8e5d6d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae8aa40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae8aa40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xde0, VA 0xffffffff8ac26540, JMP target 0xffffffff8aa6a510; Evidence ev_44db452c0b485d21099003cb9ee631f9ccf995676dc9c7f9807f926fa03a372b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa6a510); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa6a510(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xde8, VA 0xffffffff8ac26548, JMP target 0xffffffff8ae951d0; Evidence ev_3638fb668dcdbdb27d8f4b41c88a995b0619f4814d0701b0693548769f659202 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ae951d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ae951d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdf0, VA 0xffffffff8ac26550, JMP target 0xffffffff8b1d11b0; Evidence ev_1cd4e758a1024c5017778c424db60407f82915c1776b70260e1d553e27305282 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b1d11b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b1d11b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xdf8, VA 0xffffffff8ac26558, JMP target 0xffffffff8a9dae90; Evidence ev_a5d034173325c5624f4ca327edf755467ffd1991fb2610c78bfa1ff188e6d267 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9dae90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9dae90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe00, VA 0xffffffff8ac26560, JMP target 0xffffffff8aeb0030; Evidence ev_e6b741f19be7a80f4b9aa260237ca1283179c2628445d8461fc51700e01d805b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeb0030); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeb0030(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe08, VA 0xffffffff8ac26568, JMP target 0xffffffff8aebbbd0; Evidence ev_3c400c3fe4be51699559cae96cb0d7c70d89baee6b9e5dc7cf95cafbba333d28 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aebbbd0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aebbbd0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe10, VA 0xffffffff8ac26570, JMP target 0xffffffff8aecced0; Evidence ev_4861abbfe14d84d967eaee7d561431ea03f773e52ddc1ee1eadea5b732de91b3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aecced0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aecced0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe18, VA 0xffffffff8ac26578, JMP target 0xffffffff8aeccee0; Evidence ev_b564c5169254e9db29ca3e6ee20ed6bb8f30f4cedf871ce00f6d325bd368187e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeccee0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeccee0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe20, VA 0xffffffff8ac26580, JMP target 0xffffffff8aeccf30; Evidence ev_9d305e3b8b6680a71cd8d181f9ea8574e92be26336e73465129c6cb69d88a5d3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeccf30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeccf30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe28, VA 0xffffffff8ac26588, JMP target 0xffffffff8aeccf70; Evidence ev_24b4df7f3a28eba613a3306e2bf5e872cf76ee662205de1bd4367449d73f3891 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeccf70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeccf70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe30, VA 0xffffffff8ac26590, JMP target 0xffffffff8aeccfb0; Evidence ev_f5f864d07431e4a82040600f911f5dd8f6c1a9052808b968eef57a6faaaf5d7d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeccfb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeccfb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe38, VA 0xffffffff8ac26598, JMP target 0xffffffff8aeccfe0; Evidence ev_45779d27ce97b987d42fb328f2bacb272ac599c4d54e3940bd2e68a5c0426a9b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aeccfe0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aeccfe0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe40, VA 0xffffffff8ac265a0, JMP target 0xffffffff8aede4d0; Evidence ev_4790d4cb791af3cc18e33fddf190d20a7a8ff18572af65a16112d1b0a2b3dfc0 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aede4d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aede4d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe48, VA 0xffffffff8ac265a8, JMP target 0xffffffff8aedef60; Evidence ev_67bd1c7b2e18223e48208765d55dcd1f1ec65d048d7578ba62aca13664bf48a1 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aedef60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aedef60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe50, VA 0xffffffff8ac265b0, JMP target 0xffffffff8aedf000; Evidence ev_bac672696dd9311e2ba266d0ddee8e6710ba84a94646bc7254c1a5df70f6e0db */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aedf000); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aedf000(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe58, VA 0xffffffff8ac265b8, JMP target 0xffffffff8aedf0b0; Evidence ev_68638272c18b36bc7363470d070cf49095293e159e2ea18088eb280cba092b42 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aedf0b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aedf0b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe60, VA 0xffffffff8ac265c0, JMP target 0xffffffff8aedf2e0; Evidence ev_bc85c8cea4a1bfee1c56974f719a015d24055e3359093399ccc74d1a957729d9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aedf2e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aedf2e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe68, VA 0xffffffff8ac265c8, JMP target 0xffffffff8aedf670; Evidence ev_d270e65fe6a5693bb6f69e232897cefe1ac75a6cc9c603d230d6111cdde88047 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aedf670); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aedf670(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe70, VA 0xffffffff8ac265d0, JMP target 0xffffffff8aedfee0; Evidence ev_a71846936a091fe574f6c593d4cf90ee6f1cfbfa6122682655cac03691f09b13 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aedfee0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aedfee0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe78, VA 0xffffffff8ac265d8, JMP target 0xffffffff8aef6400; Evidence ev_18b5f9e72f928fbfd6422ad2b6849b55f622b0e3ed772df9286bc7698b704d43 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aef6400); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aef6400(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe80, VA 0xffffffff8ac265e0, JMP target 0xffffffff8af04ca0; Evidence ev_b903e9c9b65d79b6312873b8bf0d37fbcfdd363753fb7c4b6883298d9f940d1f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af04ca0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af04ca0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe88, VA 0xffffffff8ac265e8, JMP target 0xffffffff8af068f0; Evidence ev_08582392a08d2b2b1321394f33d74b736d22066c1127a08d3cc2e03cd0434a2e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af068f0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af068f0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe90, VA 0xffffffff8ac265f0, JMP target 0xffffffff8aa71630; Evidence ev_0fb43b0dfd9f7c5d64a95535792b71c7b2997d02c521af9153dd417d4804f78b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa71630); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa71630(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xe98, VA 0xffffffff8ac265f8, JMP target 0xffffffff8aa71fb0; Evidence ev_2124b294bfcb2dd33a72a014273d143bc111f52b43fc04543986472ea3ed6f04 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aa71fb0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aa71fb0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xea0, VA 0xffffffff8ac26600, JMP target 0xffffffff8af1bf40; Evidence ev_7da0d1cb287168624e57ccc678c5468352def29e40bc9b51aae6f03064812335 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1bf40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1bf40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xea8, VA 0xffffffff8ac26608, JMP target 0xffffffff8af1c030; Evidence ev_fa4d0d631d420eebba91722dec6d5d4b14399b59adb9b6dd61c6ffac36a7766a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1c030); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1c030(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xeb0, VA 0xffffffff8ac26610, JMP target 0xffffffff8af1c050; Evidence ev_e345a0e575963b0c23b0473bcc0cedfb955e5de5eba7981ec450123095fe768a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af1c050); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af1c050(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xeb8, VA 0xffffffff8ac26618, JMP target 0xffffffff8af2e200; Evidence ev_26d1ea47cc396aaa05936764f4f2a99c4210ef9aa2e2511faa39a2e0e561e806 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af2e200); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af2e200(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xec0, VA 0xffffffff8ac26620, JMP target 0xffffffff8af3f4a0; Evidence ev_b3337828f291a87007c286f771b1c1cb53c5e6ab5b2c99d1f43cbe5c11e59068 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af3f4a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af3f4a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xec8, VA 0xffffffff8ac26628, JMP target 0xffffffff8b3545e0; Evidence ev_0f62d433f57581de6362c9df11da271ee9e44c018208d400af12644cca0b703a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b3545e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b3545e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xed0, VA 0xffffffff8ac26630, JMP target 0xffffffff8af45950; Evidence ev_d16f44662af65bf722b760c6a7d8c1cfd82a23b1644f03767c671e0657478701 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af45950); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af45950(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xed8, VA 0xffffffff8ac26638, JMP target 0xffffffff8af59820; Evidence ev_c83ab875cf41c6e99257f5ef11032a9ac212e10d8adaaea99df61905adf9c867 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af59820); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af59820(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xee0, VA 0xffffffff8ac26640, JMP target 0xffffffff8af5a3e0; Evidence ev_d90e6f4dd290734566a43647dcb7799cad4ad92a7228486833f80e03d13981a4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5a3e0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5a3e0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xee8, VA 0xffffffff8ac26648, JMP target 0xffffffff8af5a530; Evidence ev_15ff41daf443f1cb2aeabc62a2dae2eec3f9c0201fc348cc10ffb4c9baf59632 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5a530); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5a530(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xef0, VA 0xffffffff8ac26650, JMP target 0xffffffff8af5a700; Evidence ev_6aed43e99a2586a43cffdfc3dcfff7b09e7a9e95f45c01cffa6968e7fdec8498 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5a700); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5a700(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xef8, VA 0xffffffff8ac26658, JMP target 0xffffffff8af5a7d0; Evidence ev_9724511d34b103224f142d3bba92773b6296b29d253ad0fe93a44f7d34e2c8ff */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5a7d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5a7d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf00, VA 0xffffffff8ac26660, JMP target 0xffffffff8af5aa50; Evidence ev_3d45e49ed2fb3c45f131f381696e919a775ff179730169226e66c266d2b10258 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5aa50); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5aa50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf08, VA 0xffffffff8ac26668, JMP target 0xffffffff8af5ab60; Evidence ev_b72884bc3e1d673c327de3c0fcf2da6275aa73e01805471164d8b3d00e16ea27 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5ab60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5ab60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf10, VA 0xffffffff8ac26670, JMP target 0xffffffff8af5ac60; Evidence ev_2a8591906f8fdda6e82ce237be34aa1bbcabc18fbc541223e5dad150f4a36f52 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af5ac60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af5ac60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf18, VA 0xffffffff8ac26678, JMP target 0xffffffff8af9bed0; Evidence ev_d6d6f9182862d7bfc2531c655e6e1993fd093923a20373647ba024aa11a1db9e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8af9bed0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8af9bed0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf20, VA 0xffffffff8ac26680, JMP target 0xffffffff8afab720; Evidence ev_145f7288e71f53a6abb3f38ee592b60515f6348a74170144951d09a5fd82263a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afab720); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afab720(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf28, VA 0xffffffff8ac26688, JMP target 0xffffffff8afac030; Evidence ev_b7bce8a00cf13771b60a56d1057b755238087d90ecb8f1909f54bda5d18ff302 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afac030); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afac030(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf30, VA 0xffffffff8ac26690, JMP target 0xffffffff8afacad0; Evidence ev_ce19077ee5a97c33a094c1ac3943d9fd70f9521fffb036fca0134769ca23c0a5 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afacad0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afacad0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf38, VA 0xffffffff8ac26698, JMP target 0xffffffff8afad440; Evidence ev_88eb17bb11366c0529ecf0c6613b23d21ea0d28589000cc842d281c04e74641b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afad440); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afad440(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf40, VA 0xffffffff8ac266a0, JMP target 0xffffffff8afadb30; Evidence ev_c024131bf8925051740590e121726f7af4ca6a8690ee512c891907ecf53cd489 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afadb30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afadb30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf48, VA 0xffffffff8ac266a8, JMP target 0xffffffff8ab0e280; Evidence ev_fc068ad8b0dbf1e1149e146e351d87d74475e49d099ff878b9a5f1a5b56a5a90 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8ab0e280); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8ab0e280(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf50, VA 0xffffffff8ac266b0, JMP target 0xffffffff8afb18b0; Evidence ev_ab3845398a7dd87f2b74ec2cf36ee28a8a7ab508e025bee9e1047bb1ae4c37be */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afb18b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afb18b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf58, VA 0xffffffff8ac266b8, JMP target 0xffffffff8afb2b30; Evidence ev_96f510d0043f883ee78e7ab91802683aaefff0247b219df4711f9e78121b2ece */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afb2b30); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afb2b30(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf60, VA 0xffffffff8ac266c0, JMP target 0xffffffff8afbd0c0; Evidence ev_8e06e03d898ea2a1837d9445b8da7cf33e5d70321bce0086f224ff8c2a39c6af */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afbd0c0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afbd0c0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf68, VA 0xffffffff8ac266c8, JMP target 0xffffffff8afc0680; Evidence ev_17f641c834ef7d96749ec623d9bbeb52bb446fdbaeea066d31cec5f615366c6a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afc0680); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afc0680(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf70, VA 0xffffffff8ac266d0, JMP target 0xffffffff8afc0f40; Evidence ev_f53d252c7db5713389ee23c13a0158e5f7952e1ed90802e694e5a7e106bc42a3 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afc0f40); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afc0f40(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf78, VA 0xffffffff8ac266d8, JMP target 0xffffffff8b4a64a0; Evidence ev_4361d3f10edce5cd315068992f61b7b6dd4e83b5344fcccee4b80619d3af33df */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b4a64a0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b4a64a0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf80, VA 0xffffffff8ac266e0, JMP target 0xffffffff8afedaa0; Evidence ev_287935e10ae72c74f9b637069eef4d9530b0d66a93a4914d4682b8dc0f97d6fb */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afedaa0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afedaa0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf88, VA 0xffffffff8ac266e8, JMP target 0xffffffff8aff02d0; Evidence ev_8dc1b9e00346d1e2e93583d94a43358f12ca039cdfaecaca1c276bef60b1a0f7 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aff02d0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aff02d0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf90, VA 0xffffffff8ac266f0, JMP target 0xffffffff8aff4f10; Evidence ev_df95218690a0d8171052c0c09fae8ca612910659777fe9d5e26000387c5bbd7f */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8aff4f10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8aff4f10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xf98, VA 0xffffffff8ac266f8, JMP target 0xffffffff8afff520; Evidence ev_d09d9506bb5f1247bff9edff2f2c682614f3d0f5a64f271dad27b12c097a54dc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8afff520); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8afff520(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfa0, VA 0xffffffff8ac26700, JMP target 0xffffffff8b0179b0; Evidence ev_f67050adb0d51299feca971dc8ca248482e31262a1cb08bc2a93043c3e44d61a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b0179b0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b0179b0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfa8, VA 0xffffffff8ac26708, JMP target 0xffffffff8b667310; Evidence ev_f27e80defa689304e349bdd5bc02360c6c8843b0da73e5a461084a5cdb322db4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b667310); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b667310(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfb0, VA 0xffffffff8ac26710, JMP target 0xffffffff8b022e70; Evidence ev_40751d77b9e637d90898d6380d408402bec24e67e93a95549fd7aca21b538ab9 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b022e70); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b022e70(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfb8, VA 0xffffffff8ac26718, JMP target 0xffffffff8b022e80; Evidence ev_0faf7686e97662988b08261b609b62c0cc96660fb5d467a7b8051b44e0dcfc5d */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b022e80); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b022e80(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfc0, VA 0xffffffff8ac26720, JMP target 0xffffffff8b038e10; Evidence ev_7ed9a3b5f7c89418157233c7c775696de1922ba0d8f063308fa7c244b8b49f66 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b038e10); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b038e10(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfc8, VA 0xffffffff8ac26728, JMP target 0xffffffff8b038e60; Evidence ev_1886c3f3bbe4d86203da61d47dcbadf30ae19bd346c981605256cf23bc85ef0a */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b038e60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b038e60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfd0, VA 0xffffffff8ac26730, JMP target 0xffffffff8b038ec0; Evidence ev_5125a843d7228054a47527ef1eb83de0919184035f25027a7b08790f39670731 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b038ec0); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b038ec0(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfd8, VA 0xffffffff8ac26738, JMP target 0xffffffff8b038f60; Evidence ev_1a0ec69a4b9e5a0db730d9fa4d7e0e119503bdb7d35c296d041931627b21e9f2 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b038f60); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b038f60(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfe0, VA 0xffffffff8ac26740, JMP target 0xffffffff8b039190; Evidence ev_213a2614c15a1c60272db045007b4d2fc79814b64d21fc9b815a6f9bcf9ec9bc */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b039190); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b039190(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xfe8, VA 0xffffffff8ac26748, JMP target 0xffffffff8b039360; Evidence ev_185f384351e1489c28bf97a91a7904eb92e3d42d265cdc3e87415af3237b80d4 */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b039360); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b039360(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xff0, VA 0xffffffff8ac26750, JMP target 0xffffffff8b039680; Evidence ev_a7e0ba3c05a3759d8fd4dc33ee86bdc02903ef226bc3443bd2470cadc33f427e */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8b039680); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8b039680(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Input +0xff8, VA 0xffffffff8ac26758, JMP target 0xffffffff8a9f3b90; Evidence ev_e7d289e5f013b6879fd0c0614cc9a1d61ea827f9a40bb4ac73ed3d54004c512b */
/* Reviewed JMP semantics: TAIL_JUMP(0xffffffff8a9f3b90); register/stack arguments unchanged. */

/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_ffffffff8a9f3b90(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


