// stylerule_layout_probe.cpp — PS5 14.10 WebKit StyleRuleBase/StyleRuleFontFace layout
// Pin: WebKit-7616.1.27 @ c716fcf51af2 | x86_64 LP64 (mesmo modelo de ponteiros do PS5)
// Fundamenta: docs/VARIANT_PATH_DECODE_2026-11-12.md (oracle banda StyleRuleFontFace + rc-armor)
//
// DESCOBERTA CENTRAL (source): StyleRule.h NÃO declara NENHUM 'virtual' (grep = 0 hits).
// Dispatch = m_type bitfield + visitDerived() switch (StyleRule.cpp:81-134);
// delete via destroying-delete operator delete (StyleRule.h:86; StyleRule.cpp:136-142).
// => SEM vptr no upstream E no fork. A variante "com vptr" abaixo e hipotese de robustez.
//
// Layout derivado (NDEBUG, CHECK_REF_COUNTED_LIFECYCLE=0 — RefCounted.h:30-34):
//   [sem vptr]  rc@+0x00 u32 | typeFlags@+0x04 | m_properties@+0x08 | sizeof=0x10
//   [com vptr]  vptr@+0x00   | rc@+0x08 | typeFlags@+0x0C | m_properties@+0x10 | sizeof=0x18
//
// Build: g++ -std=c++20 -O2 -DNDEBUG -static stylerule_layout_probe.cpp -o stylerule_layout_probe

#include <cstdint>
#include <cstdio>
#include <cstddef>

#ifndef NDEBUG
#error "Compile com -DNDEBUG (modelo release: sem campos de assert do RefCountedBase)"
#endif

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Winvalid-offsetof"
#endif

// ---------- Réplicas WTF (NDEBUG) ----------

// RefCountedBase NDEBUG: apenas m_refCount u32 (RefCounted.h:162).
// m_isOwnedByMainThread/m_areThreadingChecksEnabled so existem com ASSERT_ENABLED (:163-166);
// m_deletionHasBegun/m_adoptionIsRequired so com CHECK_REF_COUNTED_LIFECYCLE (:30-34) — 0 em release.
struct RefCountedBaseNDEBUG {
    mutable uint32_t m_refCount;
};

// Ref<T> = RefPtr<T> = 1 ponteiro cru (8B em LP64) — ver nota de limitação no rodape
struct StylePropertiesOpaque;
template<typename T> struct RefNDEBUG { T* ptr; };

// ---------- Réplica StyleRuleBase (StyleRule.h:52) ----------
// Bitfields reais: unsigned m_type:5 | m_hasDocumentSecurityOrigin:1 (StyleRule.h:101-104).
// m_type = StyleRuleType::FontFace = 5 (StyleRuleType.h:38)
//   => assinatura de mineracao: u32@+0x04 in {0x00000005, 0x00000025}

// Variante A — SEM vptr (a REAL: header upstream e virtual-free; destroying-delete
// + visitDerived substituem a vtable; nenhuma funcao virtual em nenhuma classe da hierarquia)
struct StyleRuleBaseNoVptr : RefCountedBaseNDEBUG {
    uint32_t m_typeFlags; // modelo u32 dos bitfields :5+:1 (offsetof em bitfield nao e portavel)
};
struct StyleRuleFontFaceNoVptr : StyleRuleBaseNoVptr { // StyleRule.h:180 'final'
    RefNDEBUG<StylePropertiesOpaque> m_properties;     // StyleRule.h:194
};

// Variante B — COM vptr (hipotese contrafactual; serve de banda de robustez do oráculo.
// Se um fork adicionasse vptr, o seed do rc-armor teria que cair em +0x08, nao +0x00)
struct StyleRuleBaseVptr {
    void* vptr;
    uint32_t m_refCount;
    uint32_t m_typeFlags;
};
struct StyleRuleFontFaceVptr : StyleRuleBaseVptr {
    RefNDEBUG<StylePropertiesOpaque> m_properties;
};

// Réplica com bitfields DE VERDADE (prova de footprint identico ao modelo u32;
// offsetof em bit-field e extensao nao-portavel — nao usada nos CHECKs)
struct StyleRuleBaseBitfields : RefCountedBaseNDEBUG {
    unsigned m_type : 5;                    // StyleRule.h:101
    unsigned m_hasDocumentSecurityOrigin : 1; // StyleRule.h:104
};
struct StyleRuleFontFaceBitfields : StyleRuleBaseBitfields {
    RefNDEBUG<StylePropertiesOpaque> m_properties;
};

// Provas em tempo de compilacao (COMPILE-VERIFY)
static_assert(sizeof(RefCountedBaseNDEBUG) == 4, "rc u32 sozinho no release");
static_assert(offsetof(StyleRuleFontFaceNoVptr, m_refCount) == 0x00, "rc @ +0x00 (âncora rc-armor)");
static_assert(offsetof(StyleRuleFontFaceNoVptr, m_typeFlags) == 0x04, "bitfields @ +0x04");
static_assert(offsetof(StyleRuleFontFaceNoVptr, m_properties.ptr) == 0x08, "m_properties @ +0x08");
static_assert(sizeof(StyleRuleBaseNoVptr) == 8, "base = 8B sem vptr");
static_assert(sizeof(StyleRuleFontFaceNoVptr) == 16, "StyleRuleFontFace = 16B (0x10) sem vptr");
static_assert(sizeof(StyleRuleFontFaceVptr) == 24, "variante com vptr = 24B (0x18)");

// ---------- deref() NDEBUG (RefCounted.h:187-191 -> derefBase :128-146) ----------
// Semantica exata: temp = rc - 1; temp==0 => delete; senao rc = temp.
// Corolario: rc==0 NAO deleta (wrap para 0xFFFFFFFF, asserts compilados out);
// somente rc==1 deleta (1-1==0 => destroying delete => visitDerived le m_type @ +0x04).
static bool derefBaseFiresDelete(uint32_t& rc)
{
    uint32_t temp = rc - 1;
    if (!temp)
        return true; // => Deleter() => delete => destroying delete
    rc = temp;
    return false;
}

#define CHECK(obj, field, expected) do { \
    size_t off = offsetof(obj, field); \
    const char* ok = (off == (size_t)(expected)) ? "OK " : "FAIL"; \
    printf("[%s] %-46s off=0x%02zX  expected=0x%02zX\n", ok, #obj "." #field, off, (size_t)(expected)); \
    if (off != (size_t)(expected)) fail++; \
} while (0)

#define CHECK_SIZE(obj, expected) do { \
    const char* ok = (sizeof(obj) == (size_t)(expected)) ? "OK " : "FAIL"; \
    printf("[%s] sizeof(%-40s) = %2zu (0x%02zX)  expected=%zu\n", ok, #obj, sizeof(obj), sizeof(obj), (size_t)(expected)); \
    if (sizeof(obj) != (size_t)(expected)) fail++; \
} while (0)

int main() {
    int fail = 0;

    printf("== StyleRuleBase / StyleRuleFontFace @ 7616.1.27 (NDEBUG, LP64, SEM vptr) ==\n");
    CHECK(StyleRuleFontFaceNoVptr, m_refCount, 0x00);   // âncora rc-armor: deref() lê u32 @ P+0x00
    CHECK(StyleRuleFontFaceNoVptr, m_typeFlags, 0x04);  // bits0-4=m_type (5=FontFace), bit5=docSecOrigin
    CHECK(StyleRuleFontFaceNoVptr, m_properties.ptr, 0x08);
    CHECK_SIZE(StyleRuleBaseNoVptr, 8);
    CHECK_SIZE(StyleRuleFontFaceNoVptr, 16);

    printf("\n== Variante hipotetica COM vptr (banda de robustez do oráculo) ==\n");
    CHECK(StyleRuleFontFaceVptr, vptr, 0x00);
    CHECK(StyleRuleFontFaceVptr, m_refCount, 0x08);     // se vptr existisse, armor seed teria que ir a +0x08
    CHECK(StyleRuleFontFaceVptr, m_typeFlags, 0x0C);
    CHECK(StyleRuleFontFaceVptr, m_properties.ptr, 0x10);
    CHECK_SIZE(StyleRuleBaseVptr, 16);
    CHECK_SIZE(StyleRuleFontFaceVptr, 24);

    printf("\n== Equivalencia bitfields reais vs modelo u32 (mesmo footprint) ==\n");
    CHECK_SIZE(StyleRuleBaseBitfields, sizeof(StyleRuleBaseNoVptr));
    CHECK_SIZE(StyleRuleFontFaceBitfields, sizeof(StyleRuleFontFaceNoVptr));

    printf("\n== Semantica deref() NDEBUG — quando o delete dispara ==\n");
    struct { uint32_t rc; const char* tag; } cases[] = {
        { 0x00000000u, "lane zerada (WRAP: nao deleta!)" },
        { 0x00000001u, "MORTE: temp==0 -> destroying delete le m_type" },
        { 0x00000002u, "regra viva tipica (sheet+face): 2->1, so decrementa" },
        { 0x00000003u, "com wrapper CSSOM (sheet+face+CSSFontFaceRule): 3->2" },
        { 0xFFFFFFFFu, "rc-armor: nunca 0 (faltam 2^32-1 derefs)" },
    };
    for (auto& c : cases) {
        uint32_t rc = c.rc;
        bool del = derefBaseFiresDelete(rc);
        printf("  rc=0x%08X -> %-6s (rc pos=%u)  [%s]\n", c.rc, del ? "DELETE" : "ok", rc, c.tag);
    }

    printf("\n== Assinatura de mineracao (pendencia p690 do doc) ==\n");
    printf("  candidato a StyleRuleFontFace* (classe de tamanho 16B do FastMalloc):\n");
    printf("    u32@P+0x00 = rc (>0, tip. 2-3)   |   u32@P+0x04 in {0x00000005, 0x00000025}\n");
    printf("    ptr@P+0x08 = StyleProperties* (RefCounted, rc@+0x00 dele tambem >0)\n");

    printf("\n%s: %d falha(s)\n", fail ? "RESULTADO COM FALHAS" : "LAYOUT VALIDADO", fail);
    return fail ? 1 : 0;
}

// NOTA DE LIMITACAO: StyleProperties (StyleProperties.h:36-38,
// DECLARE_ALLOCATOR_WITH_HEAP_IDENTIFIER(StyleProperties) + RefCounted<StyleProperties>)
// e modelado como ponteiro opaco: dentro de StyleRuleFontFace ele so ocupa os 8B do Ref<T>;
// o tamanho do pointee NAO afeta nenhum offset/size validado aqui. MutableStyleProperties
// (subclass com Vector<PropertySetEntry> etc.) so importa se alguem forjar o pointee.
