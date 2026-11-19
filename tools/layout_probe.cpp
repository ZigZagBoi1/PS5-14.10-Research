// layout_probe.cpp — PS5 14.10 WebKit CSSFontFace offset validation
// White-box turn: replica fiel dos tipos WTF/WebCore do clone @ 616.1.27
// Compila em x64 LP64 (mesmo modelo de ponteiros do arm64 do PS5).
// Valida: m_table@+0x58, opCount@+0x60, wrapper@+0x68, m_status@+0x82.
//
// NOTE (review 2026-11-12): this replica omits the virtual-dtor vptr (CSSFontFace.h:64)
// and models Function as 16B (real: 8B per Function.h:121). The two errors CANCEL
// for every device-anchored offset (+0x58/+0x68/+0x82). Device evidence (object fits
// a 192B lane exactly) proves the SONY FORK DROPPED THE VPTR — real PS5 sizeof is
// 192, not 200. Treat sizeof=200 as x64-clone-only.
// Build: g++ -std=c++20 -O2 -DNDEBUG -static layout_probe.cpp -o layout_probe

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <new>
#include <variant>

// ---------- WTF replicas (NDEBUG: CHECK_HASHTABLE_ITERATORS=0) ----------

// RefCountedBase NDEBUG: só m_refCount (u32), padded p/ 8
struct RefCountedBaseNDEBUG {
    mutable uint32_t m_refCount;
};
template<typename T>
struct RefCountedNDEBUG : RefCountedBaseNDEBUG { };

// Ref<T>/RefPtr<T>: ponteiro cru 8B
template<typename T> struct RefNDEBUG { T* ptr; };
template<typename T> struct RefPtrNDEBUG { T* ptr; };

// WTF::Vector<T> (inline capacity 0): buffer ptr + capacity/size union = 16B
struct VectorBuffer {
    void* m_buffer;
    union { size_t m_capacity; size_t m_size; };
};
template<typename T>
struct VectorNDEBUG {
    void* m_buffer;
    size_t m_capacityAndSize;
};

// WTF::HashTable NDEBUG: SÓ m_table (8B). Metadados (tableSize[-1], mask[-2],
// keyCount[-3], deletedCount[-4]) vivem em offsets NEGATIVOS do ponteiro.
struct HashTableNDEBUG {
    void* m_table;
    // operações de metadado (para documentação — não são campos):
    // tableSize      = ((unsigned*)m_table)[-1]
    // tableSizeMask  = ((unsigned*)m_table)[-2]
    // keyCount       = ((unsigned*)m_table)[-3]
    // deletedCount   = ((unsigned*)m_table)[-4]
};

// WeakHashSet<T> NDEBUG = HashTable m_set (8B) + u32 opCount → 12B → pad 16
struct WeakHashSetNDEBUG {
    HashTableNDEBUG m_set;
    mutable uint32_t m_operationCountSinceLastCleanup;
};

// WeakPtr<T> = RefPtr<WeakPtrImpl> (8B)
struct WeakPtrNDEBUG { void* m_impl; };

// ---------- WebCore replicas ----------

// FontSelectionValue = int16 wrapper
struct FontSelectionValue { int16_t v; };

// FontSelectionRange { minimum, maximum } = 4B, align 2
struct FontSelectionRange {
    FontSelectionValue minimum;
    FontSelectionValue maximum;
};
using OptionalRange = std::optional<FontSelectionRange>; // 4B + bool = 6B (align 2)

// FontSelectionSpecifiedCapabilities: 3 × OptionalRange = 18B
struct FontSelectionSpecifiedCapabilities {
    OptionalRange weight;
    OptionalRange width;
    OptionalRange slope;
};

// FontFeatureSettings = FontTaggedSettings<int> = Vector<int-setting> = 16B
struct FontFeatureSettingsNDEBUG { VectorNDEBUG<int> m_list; };

// std::variant<Ref,Ref> = union 8B + discriminant u32 = 16B
struct PropertiesOrCSSConnection {
    std::variant<RefNDEBUG<int>, RefNDEBUG<int>> v;
};

// TimerBase: vptr + 2×double + RefPtr + Ref = 40B
//   m_unalignedNextFireTime (MonotonicTime = double)
//   m_repeatInterval (Seconds = double)
//   m_heapItem RefPtr (8B)
//   m_thread Ref (8B)
struct TimerHeapItem;
struct ThreadNDEBUG;
struct TimerBaseReplica {
    void* vptr;
    double m_unalignedNextFireTime;
    double m_repeatInterval;
    RefPtrNDEBUG<TimerHeapItem> m_heapItem;
    RefNDEBUG<ThreadNDEBUG> m_thread;
};
// Timer<TimerBase>: + Function<void()> (impl ptr + inline buf) = 16B
struct TimerReplica : TimerBaseReplica {
    void* m_functionImpl;
    void* m_functionInline[1];
};

// CSSFontFace réplica fiel — ordem exata do header @ 616.1.27
struct CSSFontFaceReplica : RefCountedNDEBUG<CSSFontFaceReplica> {
    PropertiesOrCSSConnection m_propertiesOrCSSConnection; // +0x08 (16B)
    RefPtrNDEBUG<int> m_families;                           // +0x18 (8B)
    VectorNDEBUG<int> m_ranges;                             // +0x20 (16B)
    FontFeatureSettingsNDEBUG m_featureSettings;            // +0x30 (16B)
    uint8_t m_loadingBehavior;                              // +0x40 (1B)
    // pad 3
    float m_sizeAdjust;                                     // +0x44 (4B)
    VectorNDEBUG<int> m_sources;                            // +0x48 (16B)
    WeakHashSetNDEBUG m_clients;                            // +0x58 (16B: table 8 + opCount 4 + pad)
    WeakPtrNDEBUG m_wrapper;                                // +0x68 (8B)
    FontSelectionSpecifiedCapabilities m_fontSelectionCapabilities; // +0x70 (18B)
    uint8_t m_status;                                       // +0x82
    uint8_t m_isLocalFallback;                              // +0x83
    uint8_t m_sourcesPopulated;                             // +0x84
    uint8_t m_mayBePurged;                                  // +0x85
    uint8_t m_shouldIgnoreFontLoadCompletions;              // +0x86
    uint8_t m_fontLoadTimingOverride;                       // +0x87
    uint8_t m_allowUserInstalledFonts;                      // +0x88
    // pad 7
    TimerReplica m_timeoutTimer;                            // +0x90 (56B)
};

// ---------- Validação ----------

#define CHECK(field, expected) do { \
    size_t off = offsetof(CSSFontFaceReplica, field); \
    const char* ok = (off == (expected)) ? "OK " : "FAIL"; \
    printf("[%s] %-42s off=0x%03zX  expected=0x%03zX\n", ok, #field, off, (size_t)(expected)); \
    if (off != (size_t)(expected)) fail++; \
} while (0)

int main() {
    int fail = 0;

    printf("== tipos base ==\n");
    printf("  sizeof(optional<FontSelectionRange>) = %zu (esperado 6)\n", sizeof(OptionalRange));
    printf("  sizeof(FontSelectionSpecifiedCapabilities) = %zu (esperado 18)\n", sizeof(FontSelectionSpecifiedCapabilities));
    printf("  sizeof(WeakHashSetNDEBUG) = %zu (esperado 12/16)\n", sizeof(WeakHashSetNDEBUG));
    printf("  sizeof(TimerReplica) = %zu (esperado 56)\n", sizeof(TimerReplica));
    printf("\n== CSSFontFace @ 616.1.27 (NDEBUG, LP64) ==\n");

    CHECK(m_refCount, 0x00);
    CHECK(m_propertiesOrCSSConnection, 0x08);
    CHECK(m_families, 0x18);
    CHECK(m_ranges, 0x20);
    CHECK(m_featureSettings, 0x30);
    CHECK(m_loadingBehavior, 0x40);
    CHECK(m_sizeAdjust, 0x44);
    CHECK(m_sources, 0x48);
    CHECK(m_clients.m_set.m_table, 0x58);   // ANCORA 1 (forge write)
    CHECK(m_clients.m_operationCountSinceLastCleanup, 0x60); // oráculo opCount=0
    CHECK(m_wrapper.m_impl, 0x68);           // ANCORA 2 (readback)
    CHECK(m_fontSelectionCapabilities.weight, 0x70);
    CHECK(m_fontSelectionCapabilities.slope, 0x7C);
    CHECK(m_status, 0x82);                   // ORÁCULO DEVICE
    CHECK(m_isLocalFallback, 0x83);
    CHECK(m_sourcesPopulated, 0x84);
    CHECK(m_timeoutTimer, 0x90);

    printf("\n  sizeof(CSSFontFaceReplica) = %zu (esperado 200 = 0xC8)\n", sizeof(CSSFontFaceReplica));
    if (sizeof(CSSFontFaceReplica) != 200) fail++;

    // Simulação de forge: metadados HashTable em offsets negativos
    printf("\n== HashTable metadata layout (offsets negativos de m_table) ==\n");
    unsigned mem[6] = {0xDEAD, 0xBEEF, 111, 222, 333, 444}; // [0..1]=lixo antes
    // emulando: metadata [-4..-1] = deleted, keyCount, mask, size
    unsigned* tablePtr = &mem[4];
    unsigned* meta = tablePtr;
    printf("  deletedCount[-4] = %u\n", meta[-4]);
    printf("  keyCount[-3]      = %u\n", meta[-3]);
    printf("  tableSizeMask[-2] = %u\n", meta[-2]);
    printf("  tableSize[-1]     = %u\n", meta[-1]);

    printf("\n%s: %d falha(s)\n", fail ? "RESULTADO COM FALHAS" : "LAYOUT VALIDADO", fail);
    return fail ? 1 : 0;
}
