/* handler_542.bin — REA 6.7.0 / Ghidra 12.1.4 pseudocode.
 * Input SHA256: c144e07eb8944afa6c120df60bd95ccea933d393f85699df5b51e2f7db0b00b3
 * Original trampoline RVA: 0x265d30; selected implementation RVA: 0xbafe50.
 * The supplied 4096 bytes are trampoline slots, not the implementation.
 * Implementation and local helpers below use byte-matched kernel_text.bin context.
 * Pseudocode is not original source and is not intended to compile as a unit.
 * ABI fields and semantic names in Part 1 are analyst recovery from loads/stores;
 * Part 3 preserves REA decompiler text, including unknown external call types.
 * undefinedN, extraout_*, register intrinsics and invalidInstructionException are
 * decompiler artifacts, not verified C behavior. Address constants are kernel RVAs.
 */
#include <stdint.h>
#include <stddef.h>
struct proc_recovered;
struct cred_recovered;
/* Verified field offsets, not a complete ABI declaration. */
struct thread_recovered {
    uint8_t unknown_000[0x8];
    struct proc_recovered *process; /* +0x008 */
    uint8_t unknown_010[0x130];
    struct cred_recovered *credential; /* +0x140 */
    uint8_t unknown_148[0x2c0];
    uint64_t syscall_retval[2]; /* +0x408; only used where stores establish it */
};
_Static_assert(offsetof(struct thread_recovered, process)==0x8,"process offset");
_Static_assert(offsetof(struct thread_recovered, credential)==0x140,"credential offset");
_Static_assert(offsetof(struct thread_recovered, syscall_retval)==0x408,"retval offset");

/* PART 1 — ANALYST RECOVERED TYPES AND READABLE BOUNDARY */

/* Event-flag-style object: observed allocation size 0x58. */
struct event_object_110 {
    uint64_t pattern; /* +0x00 */
    uint8_t unknown_08[0x18];
    uint8_t lock_20[8];
    uint8_t wait_channel_28[0x10];
    void *waiter_head; /* +0x38 */
    void *waiter_tail_link; /* +0x40 */
    uint32_t attributes; /* +0x48 */
    uint32_t waiter_count; /* +0x4c */
    uint32_t shared_references; /* +0x50 */
    uint32_t creator_pid; /* +0x54 */
};
_Static_assert(sizeof(struct event_object_110)==0x58,"object layout");
struct sys_542_args {
    int32_t handle; uint32_t pad_04;
    uint64_t requested_pattern; /* +0x08, must be nonzero */
    uint32_t mode; uint32_t pad_14; /* +0x10 */
    uint64_t *user_observed_pattern; /* +0x18, optional */
    uint32_t *user_timeout; /* +0x20, optional in/out budget */
};
/* Assembly-correct repair of raw decompiler's external tail-jump artifact. */
int recovered_bafff0(uint32_t *kernel_timeout, uint32_t *user_timeout) {
    access_audit_134f297();
    return copyout_like_2591d0(kernel_timeout,user_timeout,4);
}

/* Semantic reconstruction of the first REA-disassembled JMP; no return address is pushed. */
int handler_542_trampoline(struct thread_recovered *td, const void *uap) {
    return implementation_at_rva_00bafe50(td, uap); /* tail call */
}


/* PART 2 — ORIGINAL TRAMPOLINE: REA may emit halt_baddata because the target is outside the imported trampoline region. This is a decompiler artifact: the actual instruction is a direct tail jump to the Part 3 target, preserving incoming registers. Verbatim REA pseudocode; evidence ev_fbdf6fe4b71f8c15d6060bc972b0eb51d682de18216e6bde59c0fb34b89fe62a. */


/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_00bafe50(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Every supplied slot is an independent direct tail jump; this is a lossless target inventory,
 * not an indexed dispatch instruction in sys_542. Unused CC bytes are listed in .asm. */
static const struct { uint32_t file_offset, trampoline_rva, target_rva; } original_slots[512] = {

    {0x000, 0x00265d30, 0x00bafe50},
    {0x008, 0x00265d38, 0x00bb0030},
    {0x010, 0x00265d40, 0x00bb0150},
    {0x018, 0x00265d48, 0x00bb01d0},
    {0x020, 0x00265d50, 0x00bb0280},
    {0x028, 0x00265d58, 0x00aba540},
    {0x030, 0x00265d60, 0x00abbe60},
    {0x038, 0x00265d68, 0x00c16020},
    {0x040, 0x00265d70, 0x00c16270},
    {0x048, 0x00265d78, 0x00c16720},
    {0x050, 0x00265d80, 0x00c16880},
    {0x058, 0x00265d88, 0x00c163d0},
    {0x060, 0x00265d90, 0x00c164f0},
    {0x068, 0x00265d98, 0x00c165d0},
    {0x070, 0x00265da0, 0x00c16660},
    {0x078, 0x00265da8, 0x00ac7240},
    {0x080, 0x00265db0, 0x00ac73c0},
    {0x088, 0x00265db8, 0x00abc510},
    {0x090, 0x00265dc0, 0x004f5e60},
    {0x098, 0x00265dc8, 0x00602fe0},
    {0x0a0, 0x00265dd0, 0x00603260},
    {0x0a8, 0x00265dd8, 0x006034e0},
    {0x0b0, 0x00265de0, 0x00603710},
    {0x0b8, 0x00265de8, 0x006039d0},
    {0x0c0, 0x00265df0, 0x00abac50},
    {0x0c8, 0x00265df8, 0x008fc610},
    {0x0d0, 0x00265e00, 0x004e1a70},
    {0x0d8, 0x00265e08, 0x00abc5f0},
    {0x0e0, 0x00265e10, 0x00a367e0},
    {0x0e8, 0x00265e18, 0x00ca0630},
    {0x0f0, 0x00265e20, 0x00a368e0},
    {0x0f8, 0x00265e28, 0x0072ecc0},
    {0x100, 0x00265e30, 0x004f7370},
    {0x108, 0x00265e38, 0x00a36b00},
    {0x110, 0x00265e40, 0x00a36b90},
    {0x118, 0x00265e48, 0x00abc710},
    {0x120, 0x00265e50, 0x005a7f60},
    {0x128, 0x00265e58, 0x00a36bc0},
    {0x130, 0x00265e60, 0x00abca10},
    {0x138, 0x00265e68, 0x00abcc00},
    {0x140, 0x00265e70, 0x00438c90},
    {0x148, 0x00265e78, 0x008d2570},
    {0x150, 0x00265e80, 0x00abd0f0},
    {0x158, 0x00265e88, 0x00a37650},
    {0x160, 0x00265e90, 0x00abd430},
    {0x168, 0x00265e98, 0x007dcd40},
    {0x170, 0x00265ea0, 0x008d25a0},
    {0x178, 0x00265ea8, 0x00abd4f0},
    {0x180, 0x00265eb0, 0x00603c90},
    {0x188, 0x00265eb8, 0x00604cf0},
    {0x190, 0x00265ec0, 0x004a2850},
    {0x198, 0x00265ec8, 0x00abd540},
    {0x1a0, 0x00265ed0, 0x0091c640},
    {0x1a8, 0x00265ed8, 0x0091cc70},
    {0x1b0, 0x00265ee0, 0x00438e30},
    {0x1b8, 0x00265ee8, 0x00439070},
    {0x1c0, 0x00265ef0, 0x00439150},
    {0x1c8, 0x00265ef8, 0x004393a0},
    {0x1d0, 0x00265f00, 0x006be4d0},
    {0x1d8, 0x00265f08, 0x00abd930},
    {0x1e0, 0x00265f10, 0x006be5c0},
    {0x1e8, 0x00265f18, 0x006be800},
    {0x1f0, 0x00265f20, 0x00a90e10},
    {0x1f8, 0x00265f28, 0x004a2de0},
    {0x200, 0x00265f30, 0x00abdad0},
    {0x208, 0x00265f38, 0x00a37660},
    {0x210, 0x00265f40, 0x00abe1c0},
    {0x218, 0x00265f48, 0x00abe7b0},
    {0x220, 0x00265f50, 0x009f81f0},
    {0x228, 0x00265f58, 0x00be9510},
    {0x230, 0x00265f60, 0x009a7d10},
    {0x238, 0x00265f68, 0x009a9560},
    {0x240, 0x00265f70, 0x009a9e10},
    {0x248, 0x00265f78, 0x009a9f40},
    {0x250, 0x00265f80, 0x008fb440},
    {0x258, 0x00265f88, 0x004a31a0},
    {0x260, 0x00265f90, 0x00abe8b0},
    {0x268, 0x00265f98, 0x009ab1f0},
    {0x270, 0x00265fa0, 0x00abb980},
    {0x278, 0x00265fa8, 0x006f92e0},
    {0x280, 0x00265fb0, 0x00434da0},
    {0x288, 0x00265fb8, 0x00434db0},
    {0x290, 0x00265fc0, 0x00434dc0},
    {0x298, 0x00265fc8, 0x00437d90},
    {0x2a0, 0x00265fd0, 0x00438280},
    {0x2a8, 0x00265fd8, 0x00ae6690},
    {0x2b0, 0x00265fe0, 0x00ae6580},
    {0x2b8, 0x00265fe8, 0x004490d0},
    {0x2c0, 0x00265ff0, 0x000a6dc0},
    {0x2c8, 0x00265ff8, 0x0044aa70},
    {0x2d0, 0x00266000, 0x009b6110},
    {0x2d8, 0x00266008, 0x000a7670},
    {0x2e0, 0x00266010, 0x000a7850},
    {0x2e8, 0x00266018, 0x000a7880},
    {0x2f0, 0x00266020, 0x00452040},
    {0x2f8, 0x00266028, 0x00454cc0},
    {0x300, 0x00266030, 0x00457820},
    {0x308, 0x00266038, 0x0046df70},
    {0x310, 0x00266040, 0x0046e080},
    {0x318, 0x00266048, 0x00472990},
    {0x320, 0x00266050, 0x004733b0},
    {0x328, 0x00266058, 0x004738b0},
    {0x330, 0x00266060, 0x00474250},
    {0x338, 0x00266068, 0x00474db0},
    {0x340, 0x00266070, 0x0047cff0},
    {0x348, 0x00266078, 0x0021dff0},
    {0x350, 0x00266080, 0x00490300},
    {0x358, 0x00266088, 0x00490db0},
    {0x360, 0x00266090, 0x00497fb0},
    {0x368, 0x00266098, 0x00497fe0},
    {0x370, 0x002660a0, 0x00498630},
    {0x378, 0x002660a8, 0x00498640},
    {0x380, 0x002660b0, 0x008f7bc0},
    {0x388, 0x002660b8, 0x008f6800},
    {0x390, 0x002660c0, 0x008f7420},
    {0x398, 0x002660c8, 0x008f9f80},
    {0x3a0, 0x002660d0, 0x005df350},
    {0x3a8, 0x002660d8, 0x005df820},
    {0x3b0, 0x002660e0, 0x00a34ce0},
    {0x3b8, 0x002660e8, 0x005e84a0},
    {0x3c0, 0x002660f0, 0x008f81f0},
    {0x3c8, 0x002660f8, 0x008f9410},
    {0x3d0, 0x00266100, 0x008fc3f0},
    {0x3d8, 0x00266108, 0x008f6c90},
    {0x3e0, 0x00266110, 0x00cb1a10},
    {0x3e8, 0x00266118, 0x00ab83a0},
    {0x3f0, 0x00266120, 0x00ab83b0},
    {0x3f8, 0x00266128, 0x008fa1c0},
    {0x400, 0x00266130, 0x008f7b40},
    {0x408, 0x00266138, 0x004a0960},
    {0x410, 0x00266140, 0x00729780},
    {0x418, 0x00266148, 0x00729790},
    {0x420, 0x00266150, 0x007297a0},
    {0x428, 0x00266158, 0x006bb590},
    {0x430, 0x00266160, 0x00ab8da0},
    {0x438, 0x00266168, 0x008fa170},
    {0x440, 0x00266170, 0x00b7f0c0},
    {0x448, 0x00266178, 0x00b7f100},
    {0x450, 0x00266180, 0x008f9cf0},
    {0x458, 0x00266188, 0x008fa740},
    {0x460, 0x00266190, 0x00552b70},
    {0x468, 0x00266198, 0x00552bf0},
    {0x470, 0x002661a0, 0x00552c50},
    {0x478, 0x002661a8, 0x00552c80},
    {0x480, 0x002661b0, 0x00552cb0},
    {0x488, 0x002661b8, 0x00552ce0},
    {0x490, 0x002661c0, 0x00b7e800},
    {0x498, 0x002661c8, 0x00b7ebe0},
    {0x4a0, 0x002661d0, 0x00b7ef70},
    {0x4a8, 0x002661d8, 0x00c06d30},
    {0x4b0, 0x002661e0, 0x00792690},
    {0x4b8, 0x002661e8, 0x005e8b20},
    {0x4c0, 0x002661f0, 0x00552d10},
    {0x4c8, 0x002661f8, 0x00b7f160},
    {0x4d0, 0x00266200, 0x005de250},
    {0x4d8, 0x00266208, 0x00a54a30},
    {0x4e0, 0x00266210, 0x00a54a40},
    {0x4e8, 0x00266218, 0x00a54a50},
    {0x4f0, 0x00266220, 0x00a54a60},
    {0x4f8, 0x00266228, 0x00a54a80},
    {0x500, 0x00266230, 0x00a54a90},
    {0x508, 0x00266238, 0x008f9720},
    {0x510, 0x00266240, 0x00a54ab0},
    {0x518, 0x00266248, 0x008f64e0},
    {0x520, 0x00266250, 0x008f5ef0},
    {0x528, 0x00266258, 0x00a54a20},
    {0x530, 0x00266260, 0x00a54a70},
    {0x538, 0x00266268, 0x00a54aa0},
    {0x540, 0x00266270, 0x006e54d0},
    {0x548, 0x00266278, 0x00b7f4b0},
    {0x550, 0x00266280, 0x0083d660},
    {0x558, 0x00266288, 0x0083d7c0},
    {0x560, 0x00266290, 0x0083dab0},
    {0x568, 0x00266298, 0x0083de80},
    {0x570, 0x002662a0, 0x008f9c80},
    {0x578, 0x002662a8, 0x008fa110},
    {0x580, 0x002662b0, 0x008f91b0},
    {0x588, 0x002662b8, 0x008fa4f0},
    {0x590, 0x002662c0, 0x008f8090},
    {0x598, 0x002662c8, 0x008fbb80},
    {0x5a0, 0x002662d0, 0x008f7b80},
    {0x5a8, 0x002662d8, 0x008f7890},
    {0x5b0, 0x002662e0, 0x008fb8a0},
    {0x5b8, 0x002662e8, 0x008f8510},
    {0x5c0, 0x002662f0, 0x008f8800},
    {0x5c8, 0x002662f8, 0x0049b080},
    {0x5d0, 0x00266300, 0x0049b090},
    {0x5d8, 0x00266308, 0x0055fa50},
    {0x5e0, 0x00266310, 0x00c34870},
    {0x5e8, 0x00266318, 0x007dccf0},
    {0x5f0, 0x00266320, 0x007dcd00},
    {0x5f8, 0x00266328, 0x007dcd10},
    {0x600, 0x00266330, 0x007dcd20},
    {0x608, 0x00266338, 0x007dcd30},
    {0x610, 0x00266340, 0x005a6c90},
    {0x618, 0x00266348, 0x005a7300},
    {0x620, 0x00266350, 0x005a7610},
    {0x628, 0x00266358, 0x005a7900},
    {0x630, 0x00266360, 0x00c9c830},
    {0x638, 0x00266368, 0x005a7f00},
    {0x640, 0x00266370, 0x005a8070},
    {0x648, 0x00266378, 0x00be8480},
    {0x650, 0x00266380, 0x0049b0a0},
    {0x658, 0x00266388, 0x0049b0c0},
    {0x660, 0x00266390, 0x0049b0d0},
    {0x668, 0x00266398, 0x0049b0e0},
    {0x670, 0x002663a0, 0x0049b0f0},
    {0x678, 0x002663a8, 0x00530720},
    {0x680, 0x002663b0, 0x00531670},
    {0x688, 0x002663b8, 0x008f96f0},
    {0x690, 0x002663c0, 0x00531230},
    {0x698, 0x002663c8, 0x00802df0},
    {0x6a0, 0x002663d0, 0x00b7f140},
    {0x6a8, 0x002663d8, 0x00ae35e0},
    {0x6b0, 0x002663e0, 0x004eee20},
    {0x6b8, 0x002663e8, 0x008fab10},
    {0x6c0, 0x002663f0, 0x008fae30},
    {0x6c8, 0x002663f8, 0x009c9220},
    {0x6d0, 0x00266400, 0x009c9100},
    {0x6d8, 0x00266408, 0x00642310},
    {0x6e0, 0x00266410, 0x00642820},
    {0x6e8, 0x00266418, 0x006436e0},
    {0x6f0, 0x00266420, 0x006438d0},
    {0x6f8, 0x00266428, 0x00643c60},
    {0x700, 0x00266430, 0x009f8290},
    {0x708, 0x00266438, 0x009fbb70},
    {0x710, 0x00266440, 0x00a45280},
    {0x718, 0x00266448, 0x00c87ca0},
    {0x720, 0x00266450, 0x009ff000},
    {0x728, 0x00266458, 0x00a00780},
    {0x730, 0x00266460, 0x00a007e0},
    {0x738, 0x00266468, 0x00abe830},
    {0x740, 0x00266470, 0x009fcf30},
    {0x748, 0x00266478, 0x005f0fc0},
    {0x750, 0x00266480, 0x008f73f0},
    {0x758, 0x00266488, 0x004f7250},
    {0x760, 0x00266490, 0x009fdad0},
    {0x768, 0x00266498, 0x009fddb0},
    {0x770, 0x002664a0, 0x009fdf10},
    {0x778, 0x002664a8, 0x006444d0},
    {0x780, 0x002664b0, 0x00650fd0},
    {0x788, 0x002664b8, 0x009fea30},
    {0x790, 0x002664c0, 0x004f7940},
    {0x798, 0x002664c8, 0x00ab8ae0},
    {0x7a0, 0x002664d0, 0x00abb660},
    {0x7a8, 0x002664d8, 0x009fe260},
    {0x7b0, 0x002664e0, 0x009fe4e0},
    {0x7b8, 0x002664e8, 0x009fe630},
    {0x7c0, 0x002664f0, 0x00798330},
    {0x7c8, 0x002664f8, 0x00abd000},
    {0x7d0, 0x00266500, 0x000fc890},
    {0x7d8, 0x00266508, 0x0049f090},
    {0x7e0, 0x00266510, 0x0049f200},
    {0x7e8, 0x00266518, 0x004c0590},
    {0x7f0, 0x00266520, 0x004c05b0},
    {0x7f8, 0x00266528, 0x000a9430},
    {0x800, 0x00266530, 0x004ca350},
    {0x808, 0x00266538, 0x004caa40},
    {0x810, 0x00266540, 0x000aa510},
    {0x818, 0x00266548, 0x004d51d0},
    {0x820, 0x00266550, 0x008111b0},
    {0x828, 0x00266558, 0x0001ae90},
    {0x830, 0x00266560, 0x004f0030},
    {0x838, 0x00266568, 0x004fbbd0},
    {0x840, 0x00266570, 0x0050ced0},
    {0x848, 0x00266578, 0x0050cee0},
    {0x850, 0x00266580, 0x0050cf30},
    {0x858, 0x00266588, 0x0050cf70},
    {0x860, 0x00266590, 0x0050cfb0},
    {0x868, 0x00266598, 0x0050cfe0},
    {0x870, 0x002665a0, 0x0051e4d0},
    {0x878, 0x002665a8, 0x0051ef60},
    {0x880, 0x002665b0, 0x0051f000},
    {0x888, 0x002665b8, 0x0051f0b0},
    {0x890, 0x002665c0, 0x0051f2e0},
    {0x898, 0x002665c8, 0x0051f670},
    {0x8a0, 0x002665d0, 0x0051fee0},
    {0x8a8, 0x002665d8, 0x00536400},
    {0x8b0, 0x002665e0, 0x00544ca0},
    {0x8b8, 0x002665e8, 0x005468f0},
    {0x8c0, 0x002665f0, 0x000b1630},
    {0x8c8, 0x002665f8, 0x000b1fb0},
    {0x8d0, 0x00266600, 0x0055bf40},
    {0x8d8, 0x00266608, 0x0055c030},
    {0x8e0, 0x00266610, 0x0055c050},
    {0x8e8, 0x00266618, 0x0056e200},
    {0x8f0, 0x00266620, 0x0057f4a0},
    {0x8f8, 0x00266628, 0x009945e0},
    {0x900, 0x00266630, 0x00585950},
    {0x908, 0x00266638, 0x00599820},
    {0x910, 0x00266640, 0x0059a3e0},
    {0x918, 0x00266648, 0x0059a530},
    {0x920, 0x00266650, 0x0059a700},
    {0x928, 0x00266658, 0x0059a7d0},
    {0x930, 0x00266660, 0x0059aa50},
    {0x938, 0x00266668, 0x0059ab60},
    {0x940, 0x00266670, 0x0059ac60},
    {0x948, 0x00266678, 0x005dbed0},
    {0x950, 0x00266680, 0x005eb720},
    {0x958, 0x00266688, 0x005ec030},
    {0x960, 0x00266690, 0x005ecad0},
    {0x968, 0x00266698, 0x005ed440},
    {0x970, 0x002666a0, 0x005edb30},
    {0x978, 0x002666a8, 0x0014e280},
    {0x980, 0x002666b0, 0x005f18b0},
    {0x988, 0x002666b8, 0x005f2b30},
    {0x990, 0x002666c0, 0x005fd0c0},
    {0x998, 0x002666c8, 0x00600680},
    {0x9a0, 0x002666d0, 0x00600f40},
    {0x9a8, 0x002666d8, 0x00ae64a0},
    {0x9b0, 0x002666e0, 0x0062daa0},
    {0x9b8, 0x002666e8, 0x006302d0},
    {0x9c0, 0x002666f0, 0x00634f10},
    {0x9c8, 0x002666f8, 0x0063f520},
    {0x9d0, 0x00266700, 0x006579b0},
    {0x9d8, 0x00266708, 0x00ca7310},
    {0x9e0, 0x00266710, 0x00662e70},
    {0x9e8, 0x00266718, 0x00662e80},
    {0x9f0, 0x00266720, 0x00678e10},
    {0x9f8, 0x00266728, 0x00678e60},
    {0xa00, 0x00266730, 0x00678ec0},
    {0xa08, 0x00266738, 0x00678f60},
    {0xa10, 0x00266740, 0x00679190},
    {0xa18, 0x00266748, 0x00679360},
    {0xa20, 0x00266750, 0x00679680},
    {0xa28, 0x00266758, 0x00033b90},
    {0xa30, 0x00266760, 0x00033ca0},
    {0xa38, 0x00266768, 0x00033d20},
    {0xa40, 0x00266770, 0x0003cf70},
    {0xa48, 0x00266778, 0x0003d0e0},
    {0xa50, 0x00266780, 0x0003d660},
    {0xa58, 0x00266788, 0x0003e100},
    {0xa60, 0x00266790, 0x0003e160},
    {0xa68, 0x00266798, 0x0003e1c0},
    {0xa70, 0x002667a0, 0x0003f070},
    {0xa78, 0x002667a8, 0x0003f0d0},
    {0xa80, 0x002667b0, 0x0003f4b0},
    {0xa88, 0x002667b8, 0x0003f510},
    {0xa90, 0x002667c0, 0x0003f570},
    {0xa98, 0x002667c8, 0x0003fbb0},
    {0xaa0, 0x002667d0, 0x0003ffc0},
    {0xaa8, 0x002667d8, 0x00040960},
    {0xab0, 0x002667e0, 0x00040b50},
    {0xab8, 0x002667e8, 0x00040c30},
    {0xac0, 0x002667f0, 0x00041630},
    {0xac8, 0x002667f8, 0x00041750},
    {0xad0, 0x00266800, 0x00041830},
    {0xad8, 0x00266808, 0x000418c0},
    {0xae0, 0x00266810, 0x00042060},
    {0xae8, 0x00266818, 0x000424d0},
    {0xaf0, 0x00266820, 0x000425a0},
    {0xaf8, 0x00266828, 0x00042600},
    {0xb00, 0x00266830, 0x00690030},
    {0xb08, 0x00266838, 0x00696cc0},
    {0xb10, 0x00266840, 0x006985d0},
    {0xb18, 0x00266848, 0x006a2050},
    {0xb20, 0x00266850, 0x006a22b0},
    {0xb28, 0x00266858, 0x006ae640},
    {0xb30, 0x00266860, 0x006ae7f0},
    {0xb38, 0x00266868, 0x001813b0},
    {0xb40, 0x00266870, 0x006befa0},
    {0xb48, 0x00266878, 0x00188040},
    {0xb50, 0x00266880, 0x006d0b00},
    {0xb58, 0x00266888, 0x006d1100},
    {0xb60, 0x00266890, 0x006d1260},
    {0xb68, 0x00266898, 0x006d13e0},
    {0xb70, 0x002668a0, 0x006d1520},
    {0xb78, 0x002668a8, 0x006d1640},
    {0xb80, 0x002668b0, 0x006d1720},
    {0xb88, 0x002668b8, 0x006dc660},
    {0xb90, 0x002668c0, 0x006dc690},
    {0xb98, 0x002668c8, 0x006dc6a0},
    {0xba0, 0x002668d0, 0x006e0920},
    {0xba8, 0x002668d8, 0x006e1440},
    {0xbb0, 0x002668e0, 0x006e1450},
    {0xbb8, 0x002668e8, 0x00189a70},
    {0xbc0, 0x002668f0, 0x00190aa0},
    {0xbc8, 0x002668f8, 0x00702970},
    {0xbd0, 0x00266900, 0x00702d60},
    {0xbd8, 0x00266908, 0x00706170},
    {0xbe0, 0x00266910, 0x007061f0},
    {0xbe8, 0x00266918, 0x0070ff00},
    {0xbf0, 0x00266920, 0x0070ffb0},
    {0xbf8, 0x00266928, 0x007101c0},
    {0xc00, 0x00266930, 0x00710320},
    {0xc08, 0x00266938, 0x00712bb0},
    {0xc10, 0x00266940, 0x00716360},
    {0xc18, 0x00266948, 0x0072f970},
    {0xc20, 0x00266950, 0x0072f990},
    {0xc28, 0x00266958, 0x0072fa20},
    {0xc30, 0x00266960, 0x00246e30},
    {0xc38, 0x00266968, 0x007647f0},
    {0xc40, 0x00266970, 0x00773710},
    {0xc48, 0x00266978, 0x00775950},
    {0xc50, 0x00266980, 0x00799e90},
    {0xc58, 0x00266988, 0x007b31f0},
    {0xc60, 0x00266990, 0x007e23a0},
    {0xc68, 0x00266998, 0x007e83e0},
    {0xc70, 0x002669a0, 0x007e8480},
    {0xc78, 0x002669a8, 0x00c3b1b0},
    {0xc80, 0x002669b0, 0x00c3c6e0},
    {0xc88, 0x002669b8, 0x00c3c690},
    {0xc90, 0x002669c0, 0x00c3c730},
    {0xc98, 0x002669c8, 0x00802220},
    {0xca0, 0x002669d0, 0x008024f0},
    {0xca8, 0x002669d8, 0x0080c570},
    {0xcb0, 0x002669e0, 0x0082b300},
    {0xcb8, 0x002669e8, 0x00920ee0},
    {0xcc0, 0x002669f0, 0x00920b90},
    {0xcc8, 0x002669f8, 0x00830810},
    {0xcd0, 0x00266a00, 0x00830f00},
    {0xcd8, 0x00266a08, 0x008352b0},
    {0xce0, 0x00266a10, 0x008352c0},
    {0xce8, 0x00266a18, 0x008352d0},
    {0xcf0, 0x00266a20, 0x008352f0},
    {0xcf8, 0x00266a28, 0x00835440},
    {0xd00, 0x00266a30, 0x00835450},
    {0xd08, 0x00266a38, 0x00835490},
    {0xd10, 0x00266a40, 0x00835ad0},
    {0xd18, 0x00266a48, 0x00850870},
    {0xd20, 0x00266a50, 0x008702f0},
    {0xd28, 0x00266a58, 0x008705d0},
    {0xd30, 0x00266a60, 0x00872af0},
    {0xd38, 0x00266a68, 0x00873800},
    {0xd40, 0x00266a70, 0x00063a40},
    {0xd48, 0x00266a78, 0x00066370},
    {0xd50, 0x00266a80, 0x000e6590},
    {0xd58, 0x00266a88, 0x000e65a0},
    {0xd60, 0x00266a90, 0x000e6760},
    {0xd68, 0x00266a98, 0x000e6870},
    {0xd70, 0x00266aa0, 0x000e7f90},
    {0xd78, 0x00266aa8, 0x000e9fa0},
    {0xd80, 0x00266ab0, 0x000ea670},
    {0xd88, 0x00266ab8, 0x000ea760},
    {0xd90, 0x00266ac0, 0x000eb0a0},
    {0xd98, 0x00266ac8, 0x000eb190},
    {0xda0, 0x00266ad0, 0x000ed000},
    {0xda8, 0x00266ad8, 0x000ed110},
    {0xdb0, 0x00266ae0, 0x0088a8a0},
    {0xdb8, 0x00266ae8, 0x0089cdf0},
    {0xdc0, 0x00266af0, 0x000eeb50},
    {0xdc8, 0x00266af8, 0x008cb250},
    {0xdd0, 0x00266b00, 0x008cb390},
    {0xdd8, 0x00266b08, 0x008d2f60},
    {0xde0, 0x00266b10, 0x008d2f90},
    {0xde8, 0x00266b18, 0x008d8230},
    {0xdf0, 0x00266b20, 0x008d8de0},
    {0xdf8, 0x00266b28, 0x008d97b0},
    {0xe00, 0x00266b30, 0x008d9910},
    {0xe08, 0x00266b38, 0x008da4c0},
    {0xe10, 0x00266b40, 0x008da570},
    {0xe18, 0x00266b48, 0x008da5b0},
    {0xe20, 0x00266b50, 0x00904c80},
    {0xe28, 0x00266b58, 0x00904e60},
    {0xe30, 0x00266b60, 0x0091d400},
    {0xe38, 0x00266b68, 0x0091d4a0},
    {0xe40, 0x00266b70, 0x00a821d0},
    {0xe48, 0x00266b78, 0x00b42120},
    {0xe50, 0x00266b80, 0x00964f30},
    {0xe58, 0x00266b88, 0x00975f50},
    {0xe60, 0x00266b90, 0x00976200},
    {0xe68, 0x00266b98, 0x0098c950},
    {0xe70, 0x00266ba0, 0x0098cc30},
    {0xe78, 0x00266ba8, 0x0098cf30},
    {0xe80, 0x00266bb0, 0x0098d6e0},
    {0xe88, 0x00266bb8, 0x0098e5d0},
    {0xe90, 0x00266bc0, 0x0098e700},
    {0xe98, 0x00266bc8, 0x00992170},
    {0xea0, 0x00266bd0, 0x00992240},
    {0xea8, 0x00266bd8, 0x000f5400},
    {0xeb0, 0x00266be0, 0x009a2320},
    {0xeb8, 0x00266be8, 0x009a5720},
    {0xec0, 0x00266bf0, 0x009ac9a0},
    {0xec8, 0x00266bf8, 0x009aca20},
    {0xed0, 0x00266c00, 0x001be640},
    {0xed8, 0x00266c08, 0x009bed20},
    {0xee0, 0x00266c10, 0x009c6050},
    {0xee8, 0x00266c18, 0x009c60d0},
    {0xef0, 0x00266c20, 0x009c6280},
    {0xef8, 0x00266c28, 0x009c6310},
    {0xf00, 0x00266c30, 0x009c6490},
    {0xf08, 0x00266c38, 0x009c65b0},
    {0xf10, 0x00266c40, 0x009c6890},
    {0xf18, 0x00266c48, 0x009c9340},
    {0xf20, 0x00266c50, 0x009c9360},
    {0xf28, 0x00266c58, 0x009c9370},
    {0xf30, 0x00266c60, 0x009c9380},
    {0xf38, 0x00266c68, 0x009dadb0},
    {0xf40, 0x00266c70, 0x009dafa0},
    {0xf48, 0x00266c78, 0x009dc860},
    {0xf50, 0x00266c80, 0x009dcc40},
    {0xf58, 0x00266c88, 0x009dce80},
    {0xf60, 0x00266c90, 0x009dd500},
    {0xf68, 0x00266c98, 0x00caacd0},
    {0xf70, 0x00266ca0, 0x009dd7d0},
    {0xf78, 0x00266ca8, 0x009dd990},
    {0xf80, 0x00266cb0, 0x009ddba0},
    {0xf88, 0x00266cb8, 0x009ddc00},
    {0xf90, 0x00266cc0, 0x009dde50},
    {0xf98, 0x00266cc8, 0x009ddeb0},
    {0xfa0, 0x00266cd0, 0x009ddff0},
    {0xfa8, 0x00266cd8, 0x009de070},
    {0xfb0, 0x00266ce0, 0x009de0f0},
    {0xfb8, 0x00266ce8, 0x009e0b90},
    {0xfc0, 0x00266cf0, 0x009e0cd0},
    {0xfc8, 0x00266cf8, 0x009e0d70},
    {0xfd0, 0x00266d00, 0x009e0ef0},
    {0xfd8, 0x00266d08, 0x009e1050},
    {0xfe0, 0x00266d10, 0x009e1490},
    {0xfe8, 0x00266d18, 0x00a065e0},
    {0xff0, 0x00266d20, 0x00101340},
    {0xff8, 0x00266d28, 0x00a32f30},
};

/* PART 3 — VERBATIM REA/GHIDRA DECOMPILATION OF IMPLEMENTATION AND LOCAL CALLEES */


/* BEGIN sys_542, RVA 0xbafe50; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xbafe50", "end": "0xbaffeb"}], "total_bytes": 412, "span_bytes": 412, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_475cb0f352c0087d229a6232189551ca4323fc35e72ae968a56831f962809a96, ev_b6c069e689a54d2a44759be433af7fe323b698604164d808246f45b2c42d2144, ev_b298f21746bd9e5889cbabbe827bf28c5e06a20bec3559b02add7c53e37c104a
 */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sys_542(long param_1,undefined4 *param_2)

{
  uint uVar1;
  undefined8 uVar2;
  code *pcVar3;
  int iVar4;
  int iVar5;
  long lVar6;
  undefined1 *puVar7;
  undefined8 *in_GS_OFFSET;
  undefined8 local_50;
  undefined1 local_44 [4];
  undefined8 local_40;
  long local_38;
  
  iVar4 = 0x16;
  local_38 = _DAT_0391c310;
  uVar1 = param_2[4];
  uVar2 = *(undefined8 *)(*(long *)(param_1 + 8) + 0xc48);
  local_40 = 0;
  if (((((uVar1 & 3) != 0) && ((uVar1 & 3) != 3)) && ((~uVar1 & 0x30) != 0)) &&
     (*(long *)(param_2 + 2) != 0)) {
    lVar6 = *(long *)(param_2 + 8);
    if (lVar6 == 0) {
      puVar7 = (undefined1 *)0x0;
    }
    else {
      func_0x00c1a3e0(*in_GS_OFFSET,0x1397f3d,0);
      puVar7 = local_44;
      iVar4 = func_0x00259280(lVar6,puVar7,4);
      if (iVar4 != 0) goto LAB_00baffc9;
    }
    lVar6 = func_0x00399ee0(uVar2,*param_2,0x110,&local_50);
    if (lVar6 == 0) {
      iVar4 = 3;
    }
    else {
      if (*(long *)(param_2 + 6) == 0) {
        iVar4 = 0;
        iVar5 = func_0x00baee80(lVar6,*(undefined8 *)(param_2 + 2),uVar1,0,puVar7);
      }
      else {
        iVar5 = func_0x00baee80(lVar6,*(undefined8 *)(param_2 + 2),uVar1,&local_40,puVar7);
        uVar2 = *(undefined8 *)(param_2 + 6);
        func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
        iVar4 = func_0x002591d0(&local_40,uVar2,8);
      }
      func_0x00399eb0(local_50);
      if (puVar7 != (undefined1 *)0x0 && iVar4 == 0) {
        iVar4 = sub_00bafff0(puVar7,*(undefined8 *)(param_2 + 8));
      }
      if (iVar5 != 0) {
        iVar4 = iVar5;
      }
    }
  }
LAB_00baffc9:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar3 = (code *)invalidInstructionException();
    (*pcVar3)();
  }
  return iVar4;
}


/* END sys_542 */


/* BEGIN sub_002591d0, RVA 0x2591d0; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x2591d0", "end": "0x259258"}, {"start": "0x259260", "end": "0x25927f"}], "total_bytes": 169, "span_bytes": 176, "non_contiguous": true, "contains_entry": true}
 * REA Evidence: ev_190630727ec083a77b4a67d456983389e08e19c91b6b6723304de8d6ca982895, ev_ad27dd927c160451a6c80c3be545ce671247136d5b7203437d230a57b15a2ade, ev_5fb8fb0c3070562e4ece63db94d6f8d55fdadabdaa0d796fbbca7da1aae30d7f
 */


undefined8 sub_002591d0(undefined8 *param_1,ulong param_2,ulong param_3)

{
  ulong uVar1;
  undefined8 *puVar2;
  long *in_GS_OFFSET;
  
  *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0x259260;
  if (param_3 != 0) {
    if (((CARRY8(param_2,param_3)) || (0x800000000000 < param_2 + param_3)) ||
       (*(char *)(*(long *)(*in_GS_OFFSET + 8) + 0x591) != '\0')) {
      *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0;
      return 0xe;
    }
    puVar2 = (undefined8 *)(param_2 & 0x7fffffffffff);
    for (uVar1 = param_3 >> 3; uVar1 != 0; uVar1 = uVar1 - 1) {
      *puVar2 = *param_1;
      param_1 = param_1 + 1;
      puVar2 = puVar2 + 1;
    }
    for (param_3 = param_3 & 7; param_3 != 0; param_3 = param_3 - 1) {
      *(undefined1 *)puVar2 = *(undefined1 *)param_1;
      param_1 = (undefined8 *)((long)param_1 + 1);
      puVar2 = (undefined8 *)((long)puVar2 + 1);
    }
  }
  *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0;
  return 0;
}


/* END sub_002591d0 */


/* BEGIN sub_00259280, RVA 0x259280; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x259280", "end": "0x259330"}, {"start": "0x259340", "end": "0x25935f"}], "total_bytes": 209, "span_bytes": 224, "non_contiguous": true, "contains_entry": true}
 * REA Evidence: ev_debd8d50b7962cd1afa8647e0ca453db15b7560ec44b6a3675c7a02558304169, ev_73da546979483f9bbd6d30c4abec1f69be544aac39b799063b0171e43b398ec9, ev_12a161297d1dd9710fceb3df06a161b8b46208acffb462f50019d243f6b946af
 */


undefined8 sub_00259280(undefined8 *param_1,undefined8 *param_2,undefined8 *param_3)

{
  ulong uVar1;
  undefined8 *extraout_RDX;
  undefined8 *puVar2;
  long *in_GS_OFFSET;
  
  if (!CARRY8((ulong)param_2,(ulong)param_3)) {
    if (((undefined1 *)((long)param_2 + (long)param_3) <= &stack0xfffffffffffffff8) ||
       ((long)&stack0x00000008 <= (long)param_2)) goto LAB_002592aa;
    param_1 = param_2;
    func_0x00258fd0();
    param_2 = param_3;
  }
  func_0x00258fe0();
  param_3 = extraout_RDX;
LAB_002592aa:
  *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0x259340;
  if (param_3 != (undefined8 *)0x0) {
    if (((CARRY8((ulong)param_1,(ulong)param_3)) ||
        ((undefined1 *)0x800000000000 < (undefined1 *)((long)param_1 + (long)param_3))) ||
       (*(char *)(*(long *)(*in_GS_OFFSET + 8) + 0x591) != '\0')) {
      *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0;
      return 0xe;
    }
    puVar2 = (undefined8 *)((ulong)param_1 & 0x7fffffffffff);
    for (uVar1 = (ulong)param_3 >> 3; uVar1 != 0; uVar1 = uVar1 - 1) {
      *param_2 = *puVar2;
      puVar2 = puVar2 + 1;
      param_2 = param_2 + 1;
    }
    for (uVar1 = (ulong)param_3 & 7; uVar1 != 0; uVar1 = uVar1 - 1) {
      *(undefined1 *)param_2 = *(undefined1 *)puVar2;
      puVar2 = (undefined8 *)((long)puVar2 + 1);
      param_2 = (undefined8 *)((long)param_2 + 1);
    }
  }
  *(undefined8 *)(in_GS_OFFSET[4] + 0x108) = 0;
  return 0;
}


/* END sub_00259280 */


/* BEGIN sub_00609940, RVA 0x609940; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x609940", "end": "0x609954"}], "total_bytes": 21, "span_bytes": 21, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_685a433cbf20575e8bdde91ed2b353e21c71da9208c2985001002a72634e68c6, ev_b20537780310e3c8ced7415109b744b41baba469fc0dc1918d08b8635aed1e73, ev_afa176b34baacfb362d432e9d47a4f9e963312aad89192d86435d9391719b636
 */


bool sub_00609940(void)

{
  int iVar1;
  
  iVar1 = func_0x005a4e50();
  return iVar1 == 1;
}


/* END sub_00609940 */


/* BEGIN sub_00baee80, RVA 0xbaee80; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xbaee80", "end": "0xbaf06b"}, {"start": "0xbaf070", "end": "0xbaf3f2"}], "total_bytes": 1391, "span_bytes": 1395, "non_contiguous": true, "contains_entry": true}
 * REA Evidence: ev_759fdcc3f77c2721b4f38f526540b9f4f95f23c809f923a033036ba8f57146bc, ev_aab1931641e1774e062bf5f0281336d264e3982dac909e5a7e0536718cc512f5, ev_ebdfd7348ebad1c96dcc4f0a6222cc2505b8a6186d8370b4a0ff84b654d5de92
 */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sub_00baee80(ulong *param_1,ulong param_2,uint param_3,ulong *param_4,uint *param_5)

{
  ulong *puVar1;
  long lVar2;
  ulong ****ppppuVar3;
  bool bVar4;
  code *pcVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  ulong uVar10;
  long lVar11;
  ulong ***pppuVar12;
  uint uVar13;
  int iVar14;
  ulong uVar15;
  ulong ****ppppuVar16;
  undefined8 uVar17;
  long *in_GS_OFFSET;
  ulong local_98;
  long local_90;
  ulong local_88;
  long local_80;
  long local_78;
  long local_70;
  ulong ***local_68;
  ulong **local_60;
  long local_58;
  ulong local_50;
  ulong local_48;
  uint local_40;
  int local_3c;
  long local_38;
  
  puVar1 = param_1 + 4;
  local_38 = _DAT_0391c310;
  func_0x004c6a00(puVar1,0,0,0);
  uVar10 = param_1[9];
  if ((uVar10 & 0x1000) != 0) {
    func_0x004c6fa0(puVar1,0,0,0);
    iVar6 = 0xd;
    goto LAB_00baf325;
  }
  if (((uVar10 & 0x10) != 0) && (*(int *)((long)param_1 + 0x4c) != 0)) {
    func_0x004c6fa0(puVar1,0,0,0);
    iVar6 = 1;
    goto LAB_00baf325;
  }
  uVar15 = *param_1;
  if ((param_3 & 1) == 0) {
    if ((uVar15 & param_2) == 0) {
LAB_00baef7f:
      lVar2 = *in_GS_OFFSET;
      local_3c = 0;
      local_48 = 0;
      local_58 = lVar2;
      local_50 = param_2;
      local_40 = param_3;
      if ((uVar10 & 1) == 0) {
        ppppuVar16 = (ulong ****)(param_1 + 7);
        do {
          ppppuVar16 = (ulong ****)*ppppuVar16;
          if (ppppuVar16 == (ulong ****)0x0) goto LAB_00baf00a;
        } while (*(ushort *)((long)ppppuVar16[2] + 0x3c2) <= *(ushort *)(lVar2 + 0x3c2));
        pppuVar12 = ppppuVar16[1];
        if ((ulong ****)*pppuVar12 != ppppuVar16) {
          func_0x007f1950();
          func_0x007f20c0(0xbaf34a,ppppuVar16,ppppuVar16[1],*ppppuVar16[1]);
          pppuVar12 = ppppuVar16[1];
          uVar17 = 3;
          goto LAB_00baf3a3;
        }
        *ppppuVar16[1] = (ulong **)&local_68;
        ppppuVar16[1] = (ulong ***)&local_68;
        local_68 = (ulong ***)ppppuVar16;
        local_60 = (ulong **)pppuVar12;
      }
      else {
LAB_00baf00a:
        local_68 = (ulong ***)0x0;
        local_60 = (ulong **)param_1[8];
        *local_60 = (ulong *)&local_68;
        param_1[8] = (ulong)&local_68;
      }
      *(int *)((long)param_1 + 0x4c) = *(int *)((long)param_1 + 0x4c) + 1;
      if (param_5 == (uint *)0x0) {
        do {
          iVar8 = func_0x0073e780(param_1 + 5,param_1 + 1,0);
          iVar6 = local_3c;
        } while (iVar8 == 0 && local_3c == 0);
      }
      else {
        uVar15 = (ulong)*param_5 / 1000000;
        uVar10 = (ulong)((*param_5 % 1000000) * 1000);
        while( true ) {
          local_90 = (long)uVar10 / 1000;
          local_98 = uVar15;
          func_0x006bc2a0(lVar2,&local_78);
          lVar11 = _DAT_039203d0;
          iVar6 = func_0x00c66c80(&local_98);
          iVar7 = func_0x0073ec60(param_1 + 5,param_1 + 1,iVar6 * lVar11,0,0x100);
          func_0x006bc2a0(lVar2,&local_88);
          local_88 = local_88 - local_78;
          local_80 = local_80 - local_70;
          if ((iVar7 != 0x23 && iVar7 != 0) || (local_3c != 0)) break;
          if (local_80 < 0) {
            local_88 = local_88 - 1;
            local_80 = local_80 + 1000000000;
          }
          lVar11 = uVar15 - local_88;
          if (lVar11 == 0) {
            if ((long)uVar10 <= local_80) {
LAB_00baf1e9:
              iVar14 = (int)uVar15;
              iVar6 = 0;
              iVar8 = 0x23;
              goto LAB_00baf1fe;
            }
          }
          else {
            bVar4 = (long)uVar15 < (long)local_88;
            uVar15 = local_88;
            if (bVar4) goto LAB_00baf1e9;
          }
          uVar15 = uVar10 - local_80;
          uVar10 = uVar15 + 1000000000;
          if (-1 < (long)uVar15) {
            uVar10 = uVar15;
          }
          uVar15 = lVar11 + ((long)uVar15 >> 0x3f);
        }
        if (local_80 < 0) {
          local_88 = local_88 - 1;
          local_80 = local_80 + 1000000000;
        }
        iVar14 = (int)local_88;
        iVar6 = local_3c;
        iVar8 = 4;
        if (iVar7 != -1) {
          iVar8 = iVar7;
        }
LAB_00baf1fe:
        uVar13 = ((int)(SUB168(SEXT816(local_80) * SEXT816(0x20c49ba5e353f7cf),8) >> 7) -
                 (SUB164(SEXT816(local_80) * SEXT816(0x20c49ba5e353f7cf),0xc) >> 0x1f)) +
                 iVar14 * 1000000;
        uVar9 = *param_5 - uVar13;
        if (*param_5 < uVar13) {
          uVar9 = 0;
        }
        *param_5 = uVar9;
      }
      iVar7 = 0;
      if ((iVar8 != 0) && (iVar6 == 0)) {
        ppppuVar3 = (ulong ****)param_1[7];
        do {
          ppppuVar16 = ppppuVar3;
          if (ppppuVar16 == (ulong ****)0x0) goto LAB_00baf29d;
          ppppuVar3 = (ulong ****)*ppppuVar16;
        } while (ppppuVar16 != &local_68);
        if (ppppuVar3 == (ulong ****)0x0) {
          if ((ulong ****)*ppppuVar16[1] != &local_68) goto LAB_00baf377;
          param_1[8] = (ulong)ppppuVar16[1];
        }
        else {
          if ((ulong ****)ppppuVar3[1] != &local_68) {
            func_0x007f1950();
            func_0x007f2180(0xbaf3b2,&local_68,*ppppuVar16,(*ppppuVar16)[1],&local_68);
            func_0x00c9aa10(7,0x1339cb6,ppppuVar16,*ppppuVar16,(*ppppuVar16)[1],ppppuVar16);
                    /* WARNING: Does not return */
            pcVar5 = (code *)invalidInstructionException();
            (*pcVar5)();
          }
          if ((ulong ****)*ppppuVar16[1] != &local_68) {
LAB_00baf377:
            func_0x007f1950();
            func_0x007f20c0(0xbaf377,&local_68,ppppuVar16[1],*ppppuVar16[1]);
            pppuVar12 = ppppuVar16[1];
            uVar17 = 0xb;
LAB_00baf3a3:
            func_0x00c9aa10(uVar17,0x12fc56b,ppppuVar16,pppuVar12,*pppuVar12);
                    /* WARNING: Does not return */
            pcVar5 = (code *)invalidInstructionException();
            (*pcVar5)();
          }
          ppppuVar3[1] = ppppuVar16[1];
        }
        *ppppuVar16[1] = (ulong **)*ppppuVar16;
LAB_00baf29d:
        if (iVar8 == 0x23) {
          *param_5 = 0;
          iVar8 = 0x3c;
        }
        local_48 = *param_1;
        iVar7 = iVar8;
      }
      iVar6 = *(int *)((long)param_1 + 0x4c) + -1;
      *(int *)((long)param_1 + 0x4c) = iVar6;
      if ((iVar6 == 0 & *(byte *)((long)param_1 + 0x49) >> 4) == 1) {
        func_0x0073ef00(param_1 + 5);
      }
      func_0x004c6fa0(puVar1,0,0,0);
      if (param_4 != (ulong *)0x0) {
        *param_4 = local_48;
      }
      iVar6 = 0x55;
      if (((local_40 & 0x100) == 0) && (iVar6 = 0xd, (local_40 & 0x200) == 0)) {
        iVar6 = iVar7;
      }
      goto LAB_00baf325;
    }
    if (param_4 != (ulong *)0x0) {
      *param_4 = uVar15;
    }
    if ((param_3 & 0x10) != 0) goto LAB_00baef64;
LAB_00baef3c:
    if ((param_3 & 0x20) != 0) {
      uVar10 = ~param_2 & *param_1;
      goto LAB_00baef66;
    }
  }
  else {
    if ((uVar15 & param_2) != param_2) goto LAB_00baef7f;
    if (param_4 != (ulong *)0x0) {
      *param_4 = uVar15;
    }
    if ((param_3 & 0x10) == 0) goto LAB_00baef3c;
LAB_00baef64:
    uVar10 = 0;
LAB_00baef66:
    *param_1 = uVar10;
  }
  func_0x004c6fa0(puVar1,0,0,0);
  iVar6 = 0;
LAB_00baf325:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar5 = (code *)invalidInstructionException();
    (*pcVar5)();
  }
  return iVar6;
}


/* END sub_00baee80 */


/* BEGIN sub_00bafff0, RVA 0xbafff0; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xbafff0", "end": "0xbb0027"}], "total_bytes": 56, "span_bytes": 56, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_5febc3d7c7733714b7f64baa98722e49d522b439d249d9df8f8166df1db0ff53, ev_dfb6f69a0f133ef8b8ace418286bae5c143c3d752dccb7182009d592f001e7cd, ev_d8b45c13edc0c7e88cc6ed421b67eb7fad201986ee2eb01735db72a7b7cfb67f
 */


/* WARNING: Control flow encountered bad instruction data */

void sub_00bafff0(void)

{
  undefined8 *in_GS_OFFSET;
  
  func_0x00c1a3e0(*in_GS_OFFSET,0x134f297,0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}


/* END sub_00bafff0 */


/* BEGIN sub_00c1a3e0, RVA 0xc1a3e0; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0xc1a3e0", "end": "0xc1a4a5"}], "total_bytes": 198, "span_bytes": 198, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_5b02a6d434dfd1e956b092a96af2cd2f6f9cf6a6ef6acf53496fe909d1dd92a8, ev_15dbed26acd85854f16d37e7805d3abe74971ba5fb861115d8fa4beec0eb8aff, ev_7d48a995ced64e599c2e597f3b73b74ff3938d9e071932d12911fad54c239f73
 */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_00c1a3e0(long param_1,undefined8 param_2,int param_3)

{
  code *pcVar1;
  int iVar2;
  undefined8 uVar3;
  ulong *in_GS_OFFSET;
  
  if (*(int *)(param_1 + 0x138) != 0) {
    func_0x007f1950();
    func_0x007f18a0(0xc1a477,param_2);
    func_0x00c9aa10(0x17,0x13434da,param_2);
                    /* WARNING: Does not return */
    pcVar1 = (code *)invalidInstructionException();
    (*pcVar1)();
  }
  if ((*(uint *)(param_1 + 0xec) & 0x4000) != 0) {
    return;
  }
  if ((*(uint *)(param_1 + 0xec) & 0x100) == 0) {
    if (*(short *)(param_1 + 0x10a) < 1) {
      return;
    }
    if (param_3 != 0) {
      return;
    }
    if ((_DAT_03538910 & 0xfffffffffffffff8) == *in_GS_OFFSET) {
      return;
    }
    uVar3 = 0x127e998;
  }
  else {
    uVar3 = 0x13434f2;
  }
  func_0x0025d410(uVar3,param_2,param_1 + 0x294);
  iVar2 = func_0x00b07920();
  if ((iVar2 != 0) && (iVar2 = func_0x00609940(), iVar2 != 0)) {
    func_0x00046c60();
  }
  *(byte *)(param_1 + 0xed) = *(byte *)(param_1 + 0xed) | 0x40;
  return;
}


/* END sub_00c1a3e0 */
