/* handler_533.bin — REA 6.7.0 / Ghidra 12.1.4 pseudocode.
 * Input SHA256: ef39d6a192141b640dcdaa0ad84ac0b947da600872ac1377092a9aee1a0dbba4
 * Original trampoline RVA: 0x265cf0; selected implementation RVA: 0x705880.
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

struct memory_backing_region_533 {
    struct memory_backing_region_533 *next; /* +0x00 */
    struct memory_backing_region_533 *previous; /* +0x08 */
    uint64_t start; /* +0x10 */
    uint64_t end; /* +0x18 */
    uint32_t references; /* +0x20, LOCK ADD/XADD */
    uint8_t unknown_24[0x20];
    uint32_t allocation_context; /* +0x44 */
    uint8_t *page_counters; /* +0x48, length >> 14 allocation */
    uint8_t charged_special; /* +0x50 */
    uint8_t unknown_51[7];
};
struct memory_descriptor_payload_533 {
    void *vm_object; /* +0x00 */
    struct memory_backing_region_533 *region; /* +0x08 */
    uint32_t allowed_flags; /* +0x10 */
    uint8_t special; /* +0x14 */
    uint8_t unknown_15[3];
};
_Static_assert(sizeof(struct memory_backing_region_533)==0x58,"region allocation size");
_Static_assert(sizeof(struct memory_descriptor_payload_533)==0x18,"payload allocation size");
struct sys_533_args {
    uint64_t unused_slot_0; /* not read; original source type unknown */
    uint64_t size; /* +0x08 */
    uint32_t flags; uint32_t pad_14; /* +0x10 */
};
/* Partial credential view established by the recovered predicate helpers. */
struct cred_recovered {
    uint8_t unknown_00[0x58];
    uint64_t identity_58; /* compared with fixed 64-bit identities */
    uint8_t unknown_60[8];
    uint64_t capability_bits_68;
    uint8_t unknown_70[0x10];
    uint64_t policy_bits_80; /* byte +0x82 is bits 16..23 of this word */
};
_Static_assert(offsetof(struct cred_recovered,identity_58)==0x58,"credential identity");
_Static_assert(offsetof(struct cred_recovered,capability_bits_68)==0x68,"credential capability word");
_Static_assert(offsetof(struct cred_recovered,policy_bits_80)==0x80,"credential policy word");

/* The region reference cleanup begins BEFORE its conditional frame prologue:
 * RVA 0x7057a0 atomically decrements references, returns unless old count == 1,
 * then unlinks under the global lock, uncharges sizes, frees page counters and
 * tail-calls free(region). Seeding 0x7057b3 alone would miss that entry prefix. */

/* Semantic reconstruction of the first REA-disassembled JMP; no return address is pushed. */
int handler_533_trampoline(struct thread_recovered *td, const void *uap) {
    return implementation_at_rva_00705880(td, uap); /* tail call */
}


/* PART 2 — ORIGINAL TRAMPOLINE: REA may emit halt_baddata because the target is outside the imported trampoline region. This is a decompiler artifact: the actual instruction is a direct tail jump to the Part 3 target, preserving incoming registers. Verbatim REA pseudocode; evidence ev_3f75ce4efa4618be10f34134f8f5656826c53400119b187ef79e0d7cfa0b3089. */


/* WARNING: Control flow encountered bad instruction data */

void thunk_EXT_FUN_00705880(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}



/* Every supplied slot is an independent direct tail jump; this is a lossless target inventory,
 * not an indexed dispatch instruction in sys_533. Unused CC bytes are listed in .asm. */
static const struct { uint32_t file_offset, trampoline_rva, target_rva; } original_slots[512] = {

    {0x000, 0x00265cf0, 0x00705880},
    {0x008, 0x00265cf8, 0x00705c60},
    {0x010, 0x00265d00, 0x004f65f0},
    {0x018, 0x00265d08, 0x004f6a70},
    {0x020, 0x00265d10, 0x00bafa80},
    {0x028, 0x00265d18, 0x00bafcf0},
    {0x030, 0x00265d20, 0x00bb0330},
    {0x038, 0x00265d28, 0x00bb0490},
    {0x040, 0x00265d30, 0x00bafe50},
    {0x048, 0x00265d38, 0x00bb0030},
    {0x050, 0x00265d40, 0x00bb0150},
    {0x058, 0x00265d48, 0x00bb01d0},
    {0x060, 0x00265d50, 0x00bb0280},
    {0x068, 0x00265d58, 0x00aba540},
    {0x070, 0x00265d60, 0x00abbe60},
    {0x078, 0x00265d68, 0x00c16020},
    {0x080, 0x00265d70, 0x00c16270},
    {0x088, 0x00265d78, 0x00c16720},
    {0x090, 0x00265d80, 0x00c16880},
    {0x098, 0x00265d88, 0x00c163d0},
    {0x0a0, 0x00265d90, 0x00c164f0},
    {0x0a8, 0x00265d98, 0x00c165d0},
    {0x0b0, 0x00265da0, 0x00c16660},
    {0x0b8, 0x00265da8, 0x00ac7240},
    {0x0c0, 0x00265db0, 0x00ac73c0},
    {0x0c8, 0x00265db8, 0x00abc510},
    {0x0d0, 0x00265dc0, 0x004f5e60},
    {0x0d8, 0x00265dc8, 0x00602fe0},
    {0x0e0, 0x00265dd0, 0x00603260},
    {0x0e8, 0x00265dd8, 0x006034e0},
    {0x0f0, 0x00265de0, 0x00603710},
    {0x0f8, 0x00265de8, 0x006039d0},
    {0x100, 0x00265df0, 0x00abac50},
    {0x108, 0x00265df8, 0x008fc610},
    {0x110, 0x00265e00, 0x004e1a70},
    {0x118, 0x00265e08, 0x00abc5f0},
    {0x120, 0x00265e10, 0x00a367e0},
    {0x128, 0x00265e18, 0x00ca0630},
    {0x130, 0x00265e20, 0x00a368e0},
    {0x138, 0x00265e28, 0x0072ecc0},
    {0x140, 0x00265e30, 0x004f7370},
    {0x148, 0x00265e38, 0x00a36b00},
    {0x150, 0x00265e40, 0x00a36b90},
    {0x158, 0x00265e48, 0x00abc710},
    {0x160, 0x00265e50, 0x005a7f60},
    {0x168, 0x00265e58, 0x00a36bc0},
    {0x170, 0x00265e60, 0x00abca10},
    {0x178, 0x00265e68, 0x00abcc00},
    {0x180, 0x00265e70, 0x00438c90},
    {0x188, 0x00265e78, 0x008d2570},
    {0x190, 0x00265e80, 0x00abd0f0},
    {0x198, 0x00265e88, 0x00a37650},
    {0x1a0, 0x00265e90, 0x00abd430},
    {0x1a8, 0x00265e98, 0x007dcd40},
    {0x1b0, 0x00265ea0, 0x008d25a0},
    {0x1b8, 0x00265ea8, 0x00abd4f0},
    {0x1c0, 0x00265eb0, 0x00603c90},
    {0x1c8, 0x00265eb8, 0x00604cf0},
    {0x1d0, 0x00265ec0, 0x004a2850},
    {0x1d8, 0x00265ec8, 0x00abd540},
    {0x1e0, 0x00265ed0, 0x0091c640},
    {0x1e8, 0x00265ed8, 0x0091cc70},
    {0x1f0, 0x00265ee0, 0x00438e30},
    {0x1f8, 0x00265ee8, 0x00439070},
    {0x200, 0x00265ef0, 0x00439150},
    {0x208, 0x00265ef8, 0x004393a0},
    {0x210, 0x00265f00, 0x006be4d0},
    {0x218, 0x00265f08, 0x00abd930},
    {0x220, 0x00265f10, 0x006be5c0},
    {0x228, 0x00265f18, 0x006be800},
    {0x230, 0x00265f20, 0x00a90e10},
    {0x238, 0x00265f28, 0x004a2de0},
    {0x240, 0x00265f30, 0x00abdad0},
    {0x248, 0x00265f38, 0x00a37660},
    {0x250, 0x00265f40, 0x00abe1c0},
    {0x258, 0x00265f48, 0x00abe7b0},
    {0x260, 0x00265f50, 0x009f81f0},
    {0x268, 0x00265f58, 0x00be9510},
    {0x270, 0x00265f60, 0x009a7d10},
    {0x278, 0x00265f68, 0x009a9560},
    {0x280, 0x00265f70, 0x009a9e10},
    {0x288, 0x00265f78, 0x009a9f40},
    {0x290, 0x00265f80, 0x008fb440},
    {0x298, 0x00265f88, 0x004a31a0},
    {0x2a0, 0x00265f90, 0x00abe8b0},
    {0x2a8, 0x00265f98, 0x009ab1f0},
    {0x2b0, 0x00265fa0, 0x00abb980},
    {0x2b8, 0x00265fa8, 0x006f92e0},
    {0x2c0, 0x00265fb0, 0x00434da0},
    {0x2c8, 0x00265fb8, 0x00434db0},
    {0x2d0, 0x00265fc0, 0x00434dc0},
    {0x2d8, 0x00265fc8, 0x00437d90},
    {0x2e0, 0x00265fd0, 0x00438280},
    {0x2e8, 0x00265fd8, 0x00ae6690},
    {0x2f0, 0x00265fe0, 0x00ae6580},
    {0x2f8, 0x00265fe8, 0x004490d0},
    {0x300, 0x00265ff0, 0x000a6dc0},
    {0x308, 0x00265ff8, 0x0044aa70},
    {0x310, 0x00266000, 0x009b6110},
    {0x318, 0x00266008, 0x000a7670},
    {0x320, 0x00266010, 0x000a7850},
    {0x328, 0x00266018, 0x000a7880},
    {0x330, 0x00266020, 0x00452040},
    {0x338, 0x00266028, 0x00454cc0},
    {0x340, 0x00266030, 0x00457820},
    {0x348, 0x00266038, 0x0046df70},
    {0x350, 0x00266040, 0x0046e080},
    {0x358, 0x00266048, 0x00472990},
    {0x360, 0x00266050, 0x004733b0},
    {0x368, 0x00266058, 0x004738b0},
    {0x370, 0x00266060, 0x00474250},
    {0x378, 0x00266068, 0x00474db0},
    {0x380, 0x00266070, 0x0047cff0},
    {0x388, 0x00266078, 0x0021dff0},
    {0x390, 0x00266080, 0x00490300},
    {0x398, 0x00266088, 0x00490db0},
    {0x3a0, 0x00266090, 0x00497fb0},
    {0x3a8, 0x00266098, 0x00497fe0},
    {0x3b0, 0x002660a0, 0x00498630},
    {0x3b8, 0x002660a8, 0x00498640},
    {0x3c0, 0x002660b0, 0x008f7bc0},
    {0x3c8, 0x002660b8, 0x008f6800},
    {0x3d0, 0x002660c0, 0x008f7420},
    {0x3d8, 0x002660c8, 0x008f9f80},
    {0x3e0, 0x002660d0, 0x005df350},
    {0x3e8, 0x002660d8, 0x005df820},
    {0x3f0, 0x002660e0, 0x00a34ce0},
    {0x3f8, 0x002660e8, 0x005e84a0},
    {0x400, 0x002660f0, 0x008f81f0},
    {0x408, 0x002660f8, 0x008f9410},
    {0x410, 0x00266100, 0x008fc3f0},
    {0x418, 0x00266108, 0x008f6c90},
    {0x420, 0x00266110, 0x00cb1a10},
    {0x428, 0x00266118, 0x00ab83a0},
    {0x430, 0x00266120, 0x00ab83b0},
    {0x438, 0x00266128, 0x008fa1c0},
    {0x440, 0x00266130, 0x008f7b40},
    {0x448, 0x00266138, 0x004a0960},
    {0x450, 0x00266140, 0x00729780},
    {0x458, 0x00266148, 0x00729790},
    {0x460, 0x00266150, 0x007297a0},
    {0x468, 0x00266158, 0x006bb590},
    {0x470, 0x00266160, 0x00ab8da0},
    {0x478, 0x00266168, 0x008fa170},
    {0x480, 0x00266170, 0x00b7f0c0},
    {0x488, 0x00266178, 0x00b7f100},
    {0x490, 0x00266180, 0x008f9cf0},
    {0x498, 0x00266188, 0x008fa740},
    {0x4a0, 0x00266190, 0x00552b70},
    {0x4a8, 0x00266198, 0x00552bf0},
    {0x4b0, 0x002661a0, 0x00552c50},
    {0x4b8, 0x002661a8, 0x00552c80},
    {0x4c0, 0x002661b0, 0x00552cb0},
    {0x4c8, 0x002661b8, 0x00552ce0},
    {0x4d0, 0x002661c0, 0x00b7e800},
    {0x4d8, 0x002661c8, 0x00b7ebe0},
    {0x4e0, 0x002661d0, 0x00b7ef70},
    {0x4e8, 0x002661d8, 0x00c06d30},
    {0x4f0, 0x002661e0, 0x00792690},
    {0x4f8, 0x002661e8, 0x005e8b20},
    {0x500, 0x002661f0, 0x00552d10},
    {0x508, 0x002661f8, 0x00b7f160},
    {0x510, 0x00266200, 0x005de250},
    {0x518, 0x00266208, 0x00a54a30},
    {0x520, 0x00266210, 0x00a54a40},
    {0x528, 0x00266218, 0x00a54a50},
    {0x530, 0x00266220, 0x00a54a60},
    {0x538, 0x00266228, 0x00a54a80},
    {0x540, 0x00266230, 0x00a54a90},
    {0x548, 0x00266238, 0x008f9720},
    {0x550, 0x00266240, 0x00a54ab0},
    {0x558, 0x00266248, 0x008f64e0},
    {0x560, 0x00266250, 0x008f5ef0},
    {0x568, 0x00266258, 0x00a54a20},
    {0x570, 0x00266260, 0x00a54a70},
    {0x578, 0x00266268, 0x00a54aa0},
    {0x580, 0x00266270, 0x006e54d0},
    {0x588, 0x00266278, 0x00b7f4b0},
    {0x590, 0x00266280, 0x0083d660},
    {0x598, 0x00266288, 0x0083d7c0},
    {0x5a0, 0x00266290, 0x0083dab0},
    {0x5a8, 0x00266298, 0x0083de80},
    {0x5b0, 0x002662a0, 0x008f9c80},
    {0x5b8, 0x002662a8, 0x008fa110},
    {0x5c0, 0x002662b0, 0x008f91b0},
    {0x5c8, 0x002662b8, 0x008fa4f0},
    {0x5d0, 0x002662c0, 0x008f8090},
    {0x5d8, 0x002662c8, 0x008fbb80},
    {0x5e0, 0x002662d0, 0x008f7b80},
    {0x5e8, 0x002662d8, 0x008f7890},
    {0x5f0, 0x002662e0, 0x008fb8a0},
    {0x5f8, 0x002662e8, 0x008f8510},
    {0x600, 0x002662f0, 0x008f8800},
    {0x608, 0x002662f8, 0x0049b080},
    {0x610, 0x00266300, 0x0049b090},
    {0x618, 0x00266308, 0x0055fa50},
    {0x620, 0x00266310, 0x00c34870},
    {0x628, 0x00266318, 0x007dccf0},
    {0x630, 0x00266320, 0x007dcd00},
    {0x638, 0x00266328, 0x007dcd10},
    {0x640, 0x00266330, 0x007dcd20},
    {0x648, 0x00266338, 0x007dcd30},
    {0x650, 0x00266340, 0x005a6c90},
    {0x658, 0x00266348, 0x005a7300},
    {0x660, 0x00266350, 0x005a7610},
    {0x668, 0x00266358, 0x005a7900},
    {0x670, 0x00266360, 0x00c9c830},
    {0x678, 0x00266368, 0x005a7f00},
    {0x680, 0x00266370, 0x005a8070},
    {0x688, 0x00266378, 0x00be8480},
    {0x690, 0x00266380, 0x0049b0a0},
    {0x698, 0x00266388, 0x0049b0c0},
    {0x6a0, 0x00266390, 0x0049b0d0},
    {0x6a8, 0x00266398, 0x0049b0e0},
    {0x6b0, 0x002663a0, 0x0049b0f0},
    {0x6b8, 0x002663a8, 0x00530720},
    {0x6c0, 0x002663b0, 0x00531670},
    {0x6c8, 0x002663b8, 0x008f96f0},
    {0x6d0, 0x002663c0, 0x00531230},
    {0x6d8, 0x002663c8, 0x00802df0},
    {0x6e0, 0x002663d0, 0x00b7f140},
    {0x6e8, 0x002663d8, 0x00ae35e0},
    {0x6f0, 0x002663e0, 0x004eee20},
    {0x6f8, 0x002663e8, 0x008fab10},
    {0x700, 0x002663f0, 0x008fae30},
    {0x708, 0x002663f8, 0x009c9220},
    {0x710, 0x00266400, 0x009c9100},
    {0x718, 0x00266408, 0x00642310},
    {0x720, 0x00266410, 0x00642820},
    {0x728, 0x00266418, 0x006436e0},
    {0x730, 0x00266420, 0x006438d0},
    {0x738, 0x00266428, 0x00643c60},
    {0x740, 0x00266430, 0x009f8290},
    {0x748, 0x00266438, 0x009fbb70},
    {0x750, 0x00266440, 0x00a45280},
    {0x758, 0x00266448, 0x00c87ca0},
    {0x760, 0x00266450, 0x009ff000},
    {0x768, 0x00266458, 0x00a00780},
    {0x770, 0x00266460, 0x00a007e0},
    {0x778, 0x00266468, 0x00abe830},
    {0x780, 0x00266470, 0x009fcf30},
    {0x788, 0x00266478, 0x005f0fc0},
    {0x790, 0x00266480, 0x008f73f0},
    {0x798, 0x00266488, 0x004f7250},
    {0x7a0, 0x00266490, 0x009fdad0},
    {0x7a8, 0x00266498, 0x009fddb0},
    {0x7b0, 0x002664a0, 0x009fdf10},
    {0x7b8, 0x002664a8, 0x006444d0},
    {0x7c0, 0x002664b0, 0x00650fd0},
    {0x7c8, 0x002664b8, 0x009fea30},
    {0x7d0, 0x002664c0, 0x004f7940},
    {0x7d8, 0x002664c8, 0x00ab8ae0},
    {0x7e0, 0x002664d0, 0x00abb660},
    {0x7e8, 0x002664d8, 0x009fe260},
    {0x7f0, 0x002664e0, 0x009fe4e0},
    {0x7f8, 0x002664e8, 0x009fe630},
    {0x800, 0x002664f0, 0x00798330},
    {0x808, 0x002664f8, 0x00abd000},
    {0x810, 0x00266500, 0x000fc890},
    {0x818, 0x00266508, 0x0049f090},
    {0x820, 0x00266510, 0x0049f200},
    {0x828, 0x00266518, 0x004c0590},
    {0x830, 0x00266520, 0x004c05b0},
    {0x838, 0x00266528, 0x000a9430},
    {0x840, 0x00266530, 0x004ca350},
    {0x848, 0x00266538, 0x004caa40},
    {0x850, 0x00266540, 0x000aa510},
    {0x858, 0x00266548, 0x004d51d0},
    {0x860, 0x00266550, 0x008111b0},
    {0x868, 0x00266558, 0x0001ae90},
    {0x870, 0x00266560, 0x004f0030},
    {0x878, 0x00266568, 0x004fbbd0},
    {0x880, 0x00266570, 0x0050ced0},
    {0x888, 0x00266578, 0x0050cee0},
    {0x890, 0x00266580, 0x0050cf30},
    {0x898, 0x00266588, 0x0050cf70},
    {0x8a0, 0x00266590, 0x0050cfb0},
    {0x8a8, 0x00266598, 0x0050cfe0},
    {0x8b0, 0x002665a0, 0x0051e4d0},
    {0x8b8, 0x002665a8, 0x0051ef60},
    {0x8c0, 0x002665b0, 0x0051f000},
    {0x8c8, 0x002665b8, 0x0051f0b0},
    {0x8d0, 0x002665c0, 0x0051f2e0},
    {0x8d8, 0x002665c8, 0x0051f670},
    {0x8e0, 0x002665d0, 0x0051fee0},
    {0x8e8, 0x002665d8, 0x00536400},
    {0x8f0, 0x002665e0, 0x00544ca0},
    {0x8f8, 0x002665e8, 0x005468f0},
    {0x900, 0x002665f0, 0x000b1630},
    {0x908, 0x002665f8, 0x000b1fb0},
    {0x910, 0x00266600, 0x0055bf40},
    {0x918, 0x00266608, 0x0055c030},
    {0x920, 0x00266610, 0x0055c050},
    {0x928, 0x00266618, 0x0056e200},
    {0x930, 0x00266620, 0x0057f4a0},
    {0x938, 0x00266628, 0x009945e0},
    {0x940, 0x00266630, 0x00585950},
    {0x948, 0x00266638, 0x00599820},
    {0x950, 0x00266640, 0x0059a3e0},
    {0x958, 0x00266648, 0x0059a530},
    {0x960, 0x00266650, 0x0059a700},
    {0x968, 0x00266658, 0x0059a7d0},
    {0x970, 0x00266660, 0x0059aa50},
    {0x978, 0x00266668, 0x0059ab60},
    {0x980, 0x00266670, 0x0059ac60},
    {0x988, 0x00266678, 0x005dbed0},
    {0x990, 0x00266680, 0x005eb720},
    {0x998, 0x00266688, 0x005ec030},
    {0x9a0, 0x00266690, 0x005ecad0},
    {0x9a8, 0x00266698, 0x005ed440},
    {0x9b0, 0x002666a0, 0x005edb30},
    {0x9b8, 0x002666a8, 0x0014e280},
    {0x9c0, 0x002666b0, 0x005f18b0},
    {0x9c8, 0x002666b8, 0x005f2b30},
    {0x9d0, 0x002666c0, 0x005fd0c0},
    {0x9d8, 0x002666c8, 0x00600680},
    {0x9e0, 0x002666d0, 0x00600f40},
    {0x9e8, 0x002666d8, 0x00ae64a0},
    {0x9f0, 0x002666e0, 0x0062daa0},
    {0x9f8, 0x002666e8, 0x006302d0},
    {0xa00, 0x002666f0, 0x00634f10},
    {0xa08, 0x002666f8, 0x0063f520},
    {0xa10, 0x00266700, 0x006579b0},
    {0xa18, 0x00266708, 0x00ca7310},
    {0xa20, 0x00266710, 0x00662e70},
    {0xa28, 0x00266718, 0x00662e80},
    {0xa30, 0x00266720, 0x00678e10},
    {0xa38, 0x00266728, 0x00678e60},
    {0xa40, 0x00266730, 0x00678ec0},
    {0xa48, 0x00266738, 0x00678f60},
    {0xa50, 0x00266740, 0x00679190},
    {0xa58, 0x00266748, 0x00679360},
    {0xa60, 0x00266750, 0x00679680},
    {0xa68, 0x00266758, 0x00033b90},
    {0xa70, 0x00266760, 0x00033ca0},
    {0xa78, 0x00266768, 0x00033d20},
    {0xa80, 0x00266770, 0x0003cf70},
    {0xa88, 0x00266778, 0x0003d0e0},
    {0xa90, 0x00266780, 0x0003d660},
    {0xa98, 0x00266788, 0x0003e100},
    {0xaa0, 0x00266790, 0x0003e160},
    {0xaa8, 0x00266798, 0x0003e1c0},
    {0xab0, 0x002667a0, 0x0003f070},
    {0xab8, 0x002667a8, 0x0003f0d0},
    {0xac0, 0x002667b0, 0x0003f4b0},
    {0xac8, 0x002667b8, 0x0003f510},
    {0xad0, 0x002667c0, 0x0003f570},
    {0xad8, 0x002667c8, 0x0003fbb0},
    {0xae0, 0x002667d0, 0x0003ffc0},
    {0xae8, 0x002667d8, 0x00040960},
    {0xaf0, 0x002667e0, 0x00040b50},
    {0xaf8, 0x002667e8, 0x00040c30},
    {0xb00, 0x002667f0, 0x00041630},
    {0xb08, 0x002667f8, 0x00041750},
    {0xb10, 0x00266800, 0x00041830},
    {0xb18, 0x00266808, 0x000418c0},
    {0xb20, 0x00266810, 0x00042060},
    {0xb28, 0x00266818, 0x000424d0},
    {0xb30, 0x00266820, 0x000425a0},
    {0xb38, 0x00266828, 0x00042600},
    {0xb40, 0x00266830, 0x00690030},
    {0xb48, 0x00266838, 0x00696cc0},
    {0xb50, 0x00266840, 0x006985d0},
    {0xb58, 0x00266848, 0x006a2050},
    {0xb60, 0x00266850, 0x006a22b0},
    {0xb68, 0x00266858, 0x006ae640},
    {0xb70, 0x00266860, 0x006ae7f0},
    {0xb78, 0x00266868, 0x001813b0},
    {0xb80, 0x00266870, 0x006befa0},
    {0xb88, 0x00266878, 0x00188040},
    {0xb90, 0x00266880, 0x006d0b00},
    {0xb98, 0x00266888, 0x006d1100},
    {0xba0, 0x00266890, 0x006d1260},
    {0xba8, 0x00266898, 0x006d13e0},
    {0xbb0, 0x002668a0, 0x006d1520},
    {0xbb8, 0x002668a8, 0x006d1640},
    {0xbc0, 0x002668b0, 0x006d1720},
    {0xbc8, 0x002668b8, 0x006dc660},
    {0xbd0, 0x002668c0, 0x006dc690},
    {0xbd8, 0x002668c8, 0x006dc6a0},
    {0xbe0, 0x002668d0, 0x006e0920},
    {0xbe8, 0x002668d8, 0x006e1440},
    {0xbf0, 0x002668e0, 0x006e1450},
    {0xbf8, 0x002668e8, 0x00189a70},
    {0xc00, 0x002668f0, 0x00190aa0},
    {0xc08, 0x002668f8, 0x00702970},
    {0xc10, 0x00266900, 0x00702d60},
    {0xc18, 0x00266908, 0x00706170},
    {0xc20, 0x00266910, 0x007061f0},
    {0xc28, 0x00266918, 0x0070ff00},
    {0xc30, 0x00266920, 0x0070ffb0},
    {0xc38, 0x00266928, 0x007101c0},
    {0xc40, 0x00266930, 0x00710320},
    {0xc48, 0x00266938, 0x00712bb0},
    {0xc50, 0x00266940, 0x00716360},
    {0xc58, 0x00266948, 0x0072f970},
    {0xc60, 0x00266950, 0x0072f990},
    {0xc68, 0x00266958, 0x0072fa20},
    {0xc70, 0x00266960, 0x00246e30},
    {0xc78, 0x00266968, 0x007647f0},
    {0xc80, 0x00266970, 0x00773710},
    {0xc88, 0x00266978, 0x00775950},
    {0xc90, 0x00266980, 0x00799e90},
    {0xc98, 0x00266988, 0x007b31f0},
    {0xca0, 0x00266990, 0x007e23a0},
    {0xca8, 0x00266998, 0x007e83e0},
    {0xcb0, 0x002669a0, 0x007e8480},
    {0xcb8, 0x002669a8, 0x00c3b1b0},
    {0xcc0, 0x002669b0, 0x00c3c6e0},
    {0xcc8, 0x002669b8, 0x00c3c690},
    {0xcd0, 0x002669c0, 0x00c3c730},
    {0xcd8, 0x002669c8, 0x00802220},
    {0xce0, 0x002669d0, 0x008024f0},
    {0xce8, 0x002669d8, 0x0080c570},
    {0xcf0, 0x002669e0, 0x0082b300},
    {0xcf8, 0x002669e8, 0x00920ee0},
    {0xd00, 0x002669f0, 0x00920b90},
    {0xd08, 0x002669f8, 0x00830810},
    {0xd10, 0x00266a00, 0x00830f00},
    {0xd18, 0x00266a08, 0x008352b0},
    {0xd20, 0x00266a10, 0x008352c0},
    {0xd28, 0x00266a18, 0x008352d0},
    {0xd30, 0x00266a20, 0x008352f0},
    {0xd38, 0x00266a28, 0x00835440},
    {0xd40, 0x00266a30, 0x00835450},
    {0xd48, 0x00266a38, 0x00835490},
    {0xd50, 0x00266a40, 0x00835ad0},
    {0xd58, 0x00266a48, 0x00850870},
    {0xd60, 0x00266a50, 0x008702f0},
    {0xd68, 0x00266a58, 0x008705d0},
    {0xd70, 0x00266a60, 0x00872af0},
    {0xd78, 0x00266a68, 0x00873800},
    {0xd80, 0x00266a70, 0x00063a40},
    {0xd88, 0x00266a78, 0x00066370},
    {0xd90, 0x00266a80, 0x000e6590},
    {0xd98, 0x00266a88, 0x000e65a0},
    {0xda0, 0x00266a90, 0x000e6760},
    {0xda8, 0x00266a98, 0x000e6870},
    {0xdb0, 0x00266aa0, 0x000e7f90},
    {0xdb8, 0x00266aa8, 0x000e9fa0},
    {0xdc0, 0x00266ab0, 0x000ea670},
    {0xdc8, 0x00266ab8, 0x000ea760},
    {0xdd0, 0x00266ac0, 0x000eb0a0},
    {0xdd8, 0x00266ac8, 0x000eb190},
    {0xde0, 0x00266ad0, 0x000ed000},
    {0xde8, 0x00266ad8, 0x000ed110},
    {0xdf0, 0x00266ae0, 0x0088a8a0},
    {0xdf8, 0x00266ae8, 0x0089cdf0},
    {0xe00, 0x00266af0, 0x000eeb50},
    {0xe08, 0x00266af8, 0x008cb250},
    {0xe10, 0x00266b00, 0x008cb390},
    {0xe18, 0x00266b08, 0x008d2f60},
    {0xe20, 0x00266b10, 0x008d2f90},
    {0xe28, 0x00266b18, 0x008d8230},
    {0xe30, 0x00266b20, 0x008d8de0},
    {0xe38, 0x00266b28, 0x008d97b0},
    {0xe40, 0x00266b30, 0x008d9910},
    {0xe48, 0x00266b38, 0x008da4c0},
    {0xe50, 0x00266b40, 0x008da570},
    {0xe58, 0x00266b48, 0x008da5b0},
    {0xe60, 0x00266b50, 0x00904c80},
    {0xe68, 0x00266b58, 0x00904e60},
    {0xe70, 0x00266b60, 0x0091d400},
    {0xe78, 0x00266b68, 0x0091d4a0},
    {0xe80, 0x00266b70, 0x00a821d0},
    {0xe88, 0x00266b78, 0x00b42120},
    {0xe90, 0x00266b80, 0x00964f30},
    {0xe98, 0x00266b88, 0x00975f50},
    {0xea0, 0x00266b90, 0x00976200},
    {0xea8, 0x00266b98, 0x0098c950},
    {0xeb0, 0x00266ba0, 0x0098cc30},
    {0xeb8, 0x00266ba8, 0x0098cf30},
    {0xec0, 0x00266bb0, 0x0098d6e0},
    {0xec8, 0x00266bb8, 0x0098e5d0},
    {0xed0, 0x00266bc0, 0x0098e700},
    {0xed8, 0x00266bc8, 0x00992170},
    {0xee0, 0x00266bd0, 0x00992240},
    {0xee8, 0x00266bd8, 0x000f5400},
    {0xef0, 0x00266be0, 0x009a2320},
    {0xef8, 0x00266be8, 0x009a5720},
    {0xf00, 0x00266bf0, 0x009ac9a0},
    {0xf08, 0x00266bf8, 0x009aca20},
    {0xf10, 0x00266c00, 0x001be640},
    {0xf18, 0x00266c08, 0x009bed20},
    {0xf20, 0x00266c10, 0x009c6050},
    {0xf28, 0x00266c18, 0x009c60d0},
    {0xf30, 0x00266c20, 0x009c6280},
    {0xf38, 0x00266c28, 0x009c6310},
    {0xf40, 0x00266c30, 0x009c6490},
    {0xf48, 0x00266c38, 0x009c65b0},
    {0xf50, 0x00266c40, 0x009c6890},
    {0xf58, 0x00266c48, 0x009c9340},
    {0xf60, 0x00266c50, 0x009c9360},
    {0xf68, 0x00266c58, 0x009c9370},
    {0xf70, 0x00266c60, 0x009c9380},
    {0xf78, 0x00266c68, 0x009dadb0},
    {0xf80, 0x00266c70, 0x009dafa0},
    {0xf88, 0x00266c78, 0x009dc860},
    {0xf90, 0x00266c80, 0x009dcc40},
    {0xf98, 0x00266c88, 0x009dce80},
    {0xfa0, 0x00266c90, 0x009dd500},
    {0xfa8, 0x00266c98, 0x00caacd0},
    {0xfb0, 0x00266ca0, 0x009dd7d0},
    {0xfb8, 0x00266ca8, 0x009dd990},
    {0xfc0, 0x00266cb0, 0x009ddba0},
    {0xfc8, 0x00266cb8, 0x009ddc00},
    {0xfd0, 0x00266cc0, 0x009dde50},
    {0xfd8, 0x00266cc8, 0x009ddeb0},
    {0xfe0, 0x00266cd0, 0x009ddff0},
    {0xfe8, 0x00266cd8, 0x009de070},
    {0xff0, 0x00266ce0, 0x009de0f0},
    {0xff8, 0x00266ce8, 0x009e0b90},
};

/* PART 3 — VERBATIM REA/GHIDRA DECOMPILATION OF IMPLEMENTATION AND LOCAL CALLEES */


/* BEGIN sys_533, RVA 0x705880; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x705880", "end": "0x705c5d"}], "total_bytes": 990, "span_bytes": 990, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_3bce20ae258347e8666ccc0bee79ceb004f6f1869be17d985705fca3c18304e2, ev_c46355b5d20f48e319129eed67adfdedcc37c886d14b0162cb1b32de0121a133, ev_2cf6e61a753bafb6f38442def9d007bf517ccbf50a0ff0c574ca750ff96cccc2
 */


/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int sys_533(long param_1,long param_2)

{
  byte *pbVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  undefined4 uVar5;
  ulong uVar6;
  undefined8 *puVar7;
  long lVar8;
  long *plVar9;
  code *pcVar10;
  int iVar11;
  long lVar12;
  undefined8 *puVar13;
  undefined8 uVar14;
  long *plVar15;
  undefined8 *puVar16;
  ulong uVar17;
  bool bVar18;
  int local_44;
  long local_40;
  long local_38;
  
  local_38 = _DAT_0391c310;
  iVar11 = func_0x006095c0(*(undefined8 *)(param_1 + 0x140));
  if ((iVar11 == 0) && (iVar11 = func_0x00609620(*(undefined8 *)(param_1 + 0x140)), iVar11 == 0)) {
    iVar11 = 1;
  }
  else {
    uVar6 = *(ulong *)(param_2 + 8);
    iVar11 = 0x16;
    if (((uVar6 & 0x3fff) == 0) && (uVar4 = *(uint *)(param_2 + 0x10), (uVar4 & 0xffffffc8) == 0)) {
      uVar14 = *(undefined8 *)(param_1 + 0x140);
      uVar5 = *(undefined4 *)(*(long *)(param_1 + 8) + 0x5d0);
      lVar12 = func_0x0045da60(1,0,uVar6,uVar4,0,uVar14,
                               *(undefined4 *)(*(long *)(param_1 + 8) + 0x5c0),uVar5);
      iVar11 = 0xc;
      if (lVar12 != 0) {
        if ((uVar4 & 4) == 0) {
          bVar18 = false;
        }
        else {
          iVar11 = func_0x00609540(uVar14);
          bVar18 = true;
          if (iVar11 == 0) {
            iVar11 = func_0x00609560(uVar14);
            bVar18 = iVar11 != 0;
          }
        }
        iVar11 = func_0x002c5d00(uVar5,2,uVar6);
        if (iVar11 == 0) {
          puVar13 = (undefined8 *)func_0x00c08b50(0x58,0x2202d80,0x102);
          *(undefined4 *)((long)puVar13 + 0x44) = uVar5;
          uVar14 = func_0x00c08b50(uVar6 >> 0xe,0x2202d80,0x102);
          puVar13[9] = uVar14;
          *(bool *)(puVar13 + 10) = bVar18;
          func_0x004c6a00(0x39202e8,0,0,0);
          uVar17 = 0;
          if (bVar18 != false) {
            uVar17 = uVar6;
          }
          if (uVar17 + _DAT_039203a0 < 0x4100001) {
            puVar7 = (undefined8 *)&DAT_039202f0;
            do {
              puVar16 = puVar7;
              if (puVar16 == (undefined8 *)0x3920348) goto LAB_00705a09;
              puVar7 = (undefined8 *)*puVar16;
            } while ((ulong)(puVar7[2] - puVar16[3]) < uVar6);
            puVar7[1] = puVar13;
            *puVar16 = puVar13;
            puVar13[1] = puVar16;
            *puVar13 = puVar7;
            lVar8 = puVar16[3];
            puVar13[2] = lVar8;
            puVar13[3] = uVar6 + lVar8;
            *(undefined4 *)(puVar13 + 4) = 1;
            _DAT_039203a0 = uVar17 + _DAT_039203a0;
            func_0x004c6fa0(0x39202e8,0,0,0);
            plVar15 = (long *)func_0x00c08b50(0x18,0x2202df0,0x102);
            *plVar15 = lVar12;
            *(uint *)(plVar15 + 2) = uVar4;
            plVar15[1] = (long)puVar13;
            *(char *)((long)plVar15 + 0x14) = (char)((uVar4 & 4) >> 2);
            LOCK();
            *(int *)(puVar13 + 4) = *(int *)(puVar13 + 4) + 1;
            UNLOCK();
            func_0x007d46a0(lVar12 + 0x18,0,0);
            *(byte *)(lVar12 + 0xa2) = *(byte *)(lVar12 + 0xa2) | 6;
            func_0x004619c0(lVar12,0x2000);
            *(byte *)(lVar12 + 0xa0) = *(byte *)(lVar12 + 0xa0) | 0x10;
            *(undefined8 **)(lVar12 + 0x160) = puVar13;
            func_0x007d4eb0(lVar12 + 0x18,0,0);
            iVar11 = func_0x0072c7a0(param_1,&local_40,&local_44,0x400000,0);
            if (iVar11 == 0) {
              func_0x0072e000(local_40,3,0xe,plVar15,0x2202e88);
              plVar9 = *(long **)(*(long *)(param_1 + 8) + 0x48);
              plVar15 = plVar9 + 8;
              func_0x00c4bb20(plVar15,0,0,0);
              lVar12 = *plVar9;
              if (*(long *)(lVar12 + 8 + (long)local_44 * 0x30) == local_40) {
                pbVar1 = (byte *)(lVar12 + (long)local_44 * 0x30 + 0x30);
                *pbVar1 = *pbVar1 | 1;
              }
              func_0x00c4c4b0(plVar15,0,0);
              LOCK();
              piVar2 = (int *)(local_40 + 0x28);
              iVar3 = *piVar2;
              *piVar2 = *piVar2 + -1;
              UNLOCK();
              if (iVar3 == 1) {
                func_0x0072b380(local_40,param_1);
              }
              *(long *)(param_1 + 0x408) = (long)local_44;
            }
            else {
              func_0x00461ba0(lVar12);
              if (plVar15[1] != 0) {
                func_0x007057a0();
              }
              func_0x00c08df0(plVar15,0x2202df0);
            }
            goto LAB_00705a5c;
          }
LAB_00705a09:
          func_0x004c6fa0(0x39202e8,0,0,0);
          func_0x002c5dd0(uVar5,2,uVar6);
          func_0x00c08df0(puVar13[9],0x2202d80);
          func_0x00c08df0(puVar13,0x2202d80);
        }
        func_0x00461ba0(lVar12);
        iVar11 = 0xc;
      }
    }
  }
LAB_00705a5c:
  if (_DAT_0391c310 != local_38) {
    func_0x006fd6b0();
                    /* WARNING: Does not return */
    pcVar10 = (code *)invalidInstructionException();
    (*pcVar10)();
  }
  return iVar11;
}


/* END sys_533 */


/* BEGIN sub_00609540, RVA 0x609540; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x609540", "end": "0x60955b"}], "total_bytes": 28, "span_bytes": 28, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_69fa9d96eb420e33b8399cb44af81a1bbb7d4d94e03deab37f06d0ce490d8b73, ev_c3d1b2d048a1de65eed4d18de20896fb9b4511964116fc29b0ca4283bc0ceae5, ev_5d72b3dd941616285070dc9e453472bdd47411fcdd843c5c247d486ff31bd81e
 */


undefined8 sub_00609540(long param_1)

{
  undefined8 uVar1;
  
  if (((*(byte *)(param_1 + 0x6f) & 0x20) == 0) ||
     (uVar1 = 1, (*(byte *)(param_1 + 0x82) & 0x80) == 0)) {
    uVar1 = 0;
  }
  return uVar1;
}


/* END sub_00609540 */


/* BEGIN sub_00609560, RVA 0x609560; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x609560", "end": "0x60957b"}], "total_bytes": 28, "span_bytes": 28, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_ab24de8a18f38c184b0fdf3793f385870fcaaa95e0db07a30e3f22c631fafdb0, ev_2b5413c8ce707e4eb022cc66f9e45abcfbc33b1f00b7329a5b29c49efbac04b9, ev_08fe2c93270e50828988bb228f89c51d04acce655069cdad7d7fc651ed3e360e
 */


undefined8 sub_00609560(long param_1)

{
  undefined8 uVar1;
  
  if (((*(byte *)(param_1 + 0x6f) & 0x40) == 0) ||
     (uVar1 = 1, (*(byte *)(param_1 + 0x82) & 0x80) == 0)) {
    uVar1 = 0;
  }
  return uVar1;
}


/* END sub_00609560 */


/* BEGIN sub_006095c0, RVA 0x6095c0; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x6095c0", "end": "0x609604"}], "total_bytes": 69, "span_bytes": 69, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_885421f2ecd1a83c2e5c45488bd4230dd41aa9ee3c0aee448a7edb08cf62a173, ev_979efe405b0c3b634eaad079413c423efba3da8b16c174c388e9a8bb05043a57, ev_4027a5d3edf6222197ec1107760ba3bf9f72de07c2126fec3cff31a59de2ed80
 */


undefined8 sub_006095c0(long param_1)

{
  int iVar1;
  undefined8 uVar2;
  
  uVar2 = 1;
  if ((*(ulong *)(param_1 + 0x68) >> 0x3e & 1) == 0) {
    if (((*(ulong *)(param_1 + 0x68) >> 0x38 & 1) != 0) && (iVar1 = func_0x005a4c20(), iVar1 != 0))
    {
      return 1;
    }
    if ((*(char *)(param_1 + 0x5f) == 'A') && (iVar1 = func_0x005a59f0(), iVar1 != 0)) {
      return 1;
    }
    uVar2 = 0;
  }
  return uVar2;
}


/* END sub_006095c0 */


/* BEGIN sub_00609620, RVA 0x609620; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x609620", "end": "0x609664"}], "total_bytes": 69, "span_bytes": 69, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_3eddb6139a687ec4a7424ba490fa6f26c522c852cc45295be8e94d08c00c774d, ev_544ce068a1927997fdd2f741e91290bff92b1ee17ffffa09157801db49a4c889, ev_94571d7b70c13273dc09bacabc2611df0b3cab01726358fdfd3e99b116e7b6bb
 */


undefined8 sub_00609620(long param_1)

{
  int iVar1;
  undefined8 uVar2;
  
  uVar2 = 1;
  if ((*(ulong *)(param_1 + 0x68) >> 0x3d & 1) == 0) {
    if (((*(ulong *)(param_1 + 0x68) >> 0x38 & 1) != 0) && (iVar1 = func_0x005a4c20(), iVar1 != 0))
    {
      return 1;
    }
    if ((*(char *)(param_1 + 0x5f) == 'A') && (iVar1 = func_0x005a59f0(), iVar1 != 0)) {
      return 1;
    }
    uVar2 = 0;
  }
  return uVar2;
}


/* END sub_00609620 */


/* BEGIN sub_007057a0, RVA 0x7057a0; body {"available": true, "provenance": "ghidra-function-body-address-set", "ranges": [{"start": "0x7057a0", "end": "0x705879"}], "total_bytes": 218, "span_bytes": 218, "non_contiguous": false, "contains_entry": true}
 * REA Evidence: ev_02a6d2b798b5f8ce56aa42ac155592d76d8876ab12d691adc783197a218931bf, ev_a1252644e82ae0a5b8302db081fb5cfe70e7cdac19f5da8937e5bec69b1d6cab, ev_2987137e6ce3203a731e2edf4a879f94e2c3a3aa45607aec40fa8ea0649d2575
 */


/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Possible PIC construction at 0x00705853: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00705858) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void sub_007057a0(long *param_1)

{
  char *pcVar1;
  long *plVar2;
  long lVar3;
  int iVar4;
  uint uVar5;
  ulong uVar6;
  ulong uVar7;
  ulong uVar8;
  
  LOCK();
  plVar2 = param_1 + 4;
  lVar3 = *plVar2;
  *(int *)plVar2 = (int)*plVar2 + -1;
  UNLOCK();
  if ((int)lVar3 == 1) {
    func_0x004c6a00(0x39202e8,0,0,0);
    plVar2 = (long *)param_1[1];
    *(long **)(*param_1 + 8) = plVar2;
    *plVar2 = *param_1;
    uVar8 = param_1[3] - param_1[2];
    if ((char)param_1[10] == '\x01') {
      _DAT_039203a0 = _DAT_039203a0 - uVar8;
    }
    func_0x002c5dd0(*(undefined4 *)((long)param_1 + 0x44),2,uVar8);
    uVar6 = 0;
    if (0x3fff < uVar8) {
      iVar4 = 1;
      uVar7 = 0;
      do {
        pcVar1 = (char *)(param_1[9] + uVar7);
        uVar7 = (ulong)iVar4;
        uVar5 = ((int)uVar6 + 1) - (uint)(*pcVar1 == '\0');
        uVar6 = (ulong)uVar5;
        iVar4 = iVar4 + 1;
      } while (uVar7 < (ulong)((long)uVar8 >> 0xe));
      uVar6 = (long)(int)uVar5 << 0xe;
    }
    func_0x002c5dd0(*(undefined4 *)((long)param_1 + 0x44),3,uVar6);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
  }
  return;
}


/* END sub_007057a0 */
