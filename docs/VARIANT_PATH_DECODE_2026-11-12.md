# Variant path (+0x08) — decodificação source-side completa
Data: 2026-11-12 | Pin: WebKit-7616.1.27 @ c716fcf51af2 (canônico, arbiter #276)
White-box week (console offline até segunda). Todas as linhas citadas do pin.

## Mapa do caminho

```
teardown: CSSFontFaceSet::remove(face)               CSSFontFaceSet.cpp:250-277
  └─ face.cssConnection()                            CSSFontFace.cpp:135-145
       └─ switchOn(m_propertiesOrCSSConnection)      variant: union ptr @+0x08, index u32 @+0x0C
            ├─ [0] MutableStyleProperties → nullptr  → ramo morto (MISS benigno)
            └─ [1] StyleRuleFontFace: P = ptr @ +0x08
                 └─ m_constituentCSSConnections.remove(P)   CSSFontFaceSet.cpp:263-266
                      tabela: HashMap<StyleRuleFontFace*, CSSFontFace*>  CSSFontFaceSet.h:131
                      └─ hash(P) = IntHash<uintptr_t>(P)   HashFunctions.h:127-133
                         • hash de INTEIRO sobre o VALOR do ponteiro
                         • NUNCA derefere P durante o lookup
                         • walk lê m_table[i] (tabela), compara com P
                         ├─ P não-achado → no-op (MISS) — seguro, comprovado em device
                         ├─ P achado → value Ref<CSSFontFace>: ~Ref → deref()
                         │    RefCounted.h:187-191 deref() → derefBase():128-146
                         │    lê rc @ P+0x00; rc--; se 0 → delete P
                         │    [dangling] rc em memória liberada → crash/morte
                         │    [forge] rc@P+0x00 = 0xFFFFFFFF → nunca 0 → nunca delete → ESTÁVEL
```

## Verdades fechadas (fonte + device)

1. **Oracle poisoned-ptr é real**: hit = "bucket da tabela == P". O engine
   compara ponteiro-vs-bucket; P não é dereferido no caminho de busca. Miss
   comprovado seguro: p685–p688 (12+ cargas, incl. 0x1 = W-island seed,
   sobrevivência integral).
2. **p685 já rodou poisoned-ptr sem sabermos**: W_PREV=0x10007e4c80 como
   variant→ StyleRuleFontFace* fez o engine executar HashMap::remove sobre
   a tabela real do CSSFontFaceSet com um ponteiro para W-island. Miss
   (nenhum StyleRuleFontFace vive lá) → no-op → sobrevivemos.
3. **Gadget rc-armor**: seed rc=0xFFFFFFFF no bloco alvo P (se P cair em
   lane sob nosso controle) → cada deref decrementa 1, nunca atinge 0,
   P nunca é deletado. Com P em lane lida por dump, o rc vira um
   CONTADOR DE TOQUES do engine (read primitive por decremento observável).
4. **Semântica do discriminant [CORRIGIDO 2026-11-12 A2+compile]**: o index
   do std::variant NÃO é o hi-dword @+0x0C — é BYTE no offset +8 do variant
   = **face+0x10** (compile-verified g++ 16, libc++/libstdc++ idem shape:
   union 8B + index byte). 0 = properties (benigno), 1 = connection.
   Mineração A2 (91 dumps): index observado sempre {0, ou 0x10 que era
   hi-dword de seed W} → **o braço connection NUNCA rodou em device até
   hoje**. p685 rodou 100% no braço benigno; p690 corrigido semeia
   +0x10=1 explicitamente (dv.setUint8(0x10,1)) ao semear candidato.
   Consequência: com index=1 armado, o dtor da face deref P
   INCONDICIONALMENTE (caminho A3 §1) — lane 0x1 vira discriminador
   empírico dtor-deref vs HashMap-only.
5. **Correção do snapshot**: m_constituentCSSConnections NÃO é membro do
   CSSFontSelector (não existe no 616.1.27) — é HashMap do CSSFontFaceSet
   (CSSFontFaceSet.h:131). Os misses p686–p688 varreram bandas erradas:
   StyleRuleFontFace* são StyleRuleBase (StyleRule.h:52, alocados junto
   de rules CSS), banda de alocação ≠ T-tables ≠ W-island.

## Implicações para segunda (bancada)

- **Alvo do oracle re-target**: StyleRuleFontFace = StyleRuleBase →
  FastAllocator do StyleRuleBase heap. Bandas candidatas: onde vivem
  regras CSS (build do stylesheet), NÃO as bandas T (16KB steps) nem
  W-island. Prioridade: logs antigos com descritores de estilo —
  bandas de StyleRuleBase provavelmente visíveis em dumps de gerações
  passadas (procurar ponteiros 0x1000xxxxxx não-T/não-W em +0x08 de
  faces reais em dumps anteriores).
- **Design p689 (decider +0x82/+0x94)**: inalterado (já pré-registrado).
- **Design p690 (oracle v2)**: 5 lanes × candidatos StyleRuleFontFace*
  (banda de regras CSS), um por carga; index=1 seed; observável = hit
  (morte/crash sobrevivente com dump pós) vs miss (ALIVE limpo).
  Previsão source: hit requer P == bucket real → morte por deref em
  P+0x00 (rc em bloco não-Controlado) OU rc-armor se lane for nossa.
- **Gadget alvo do dia**: rc-armor + poisoned-ptr → se um candidato
  cair em NOSSA lane (self-address), o engine deref e NOSSO rc-armor
  segura → primeiro read-primitive real do projeto.

## Pendências abertas (para o simulador/probes)

- [ ] Mineração dos dumps p673/p685–p688: procurar valores @+0x08 que
      não sejam 0 nem nosso seed → candidatos reais StyleRuleFontFace*
      (banda alvo do p690).
- [x] Confirmar sizeof(StyleRuleBase)+0x00 rc layout (source) para
      prever rc-armor landing em lane. → FECHADO pelo A3 (abaixo).
- [ ] Simulador: emular HashMap::remove walk (bucket compare) + deref
      para validar previsões hit/miss antes da bancada.

## ERRATUM + upgrades (validação A3 — 2026-11-12, 16 CHECKs compilados, g++ 16.1.0)

1. **HashMap::remove(P) NÃO deref P.** `m_constituentCSSConnections` é
   `HashMap<StyleRuleFontFace*, CSSFontFace*>` com **value ponteiro cru**
   (CSSFontFaceSet.h:131): remove do mapa não toca refcount de ninguém.
   O deref de P ocorre **no dtor da face**: `~CSSFontFace()=default`
   (CSSFontFace.cpp:109) → dtor membros em ordem REVERSA → `~variant` →
   `~Ref<StyleRuleFontFace>` → `ptr->deref()` (Ref.h:54-61) → derefBase
   lê u32@P+0x00 (RefCounted.h:128-146,187-191). Minha frase "hit ⇒ ~Ref
   do value" estava certa no efeito, errada no mecanismo: o alvo do deref
   é P (a KEY, via dtor da face), não o value.
2. **StyleRuleBase NÃO tem vptr — nem stock nem fork.** Zero `virtual`
   em StyleRule.h; dispatch via m_type+visitDerived (StyleRule.cpp:81-134);
   delete via destroying delete operator (StyleRule.h:86, StyleRule.cpp:136-142).
   Layout REAL: rc@+0x00 (u32), typeFlags@+0x04 (m_type=5 FontFace em bits 0-4),
   m_properties@+0x08 (Ref ptr). **sizeof(StyleRuleFontFace)=16B**.
3. **rc típico de regra viva = 2** (StyleSheetContents.m_childRules
   StyleSheetContents.h:172 + variant da face CSSFontSelector.cpp:202);
   com wrapper CSSOM = 3. HIT em regra real ⇒ decremento 2→1, NÃO mata.
   Única janela de morte: rc==1 exato. rc==0 em NDEBUG faz WRAP para
   0xFFFFFFFF (não deleta!) — ASSERT compilado out.
4. **Armor confirmado**: 0xFFFFFFFF@P+0x00 estável (falta 2^32−1 derefs);
   nenhum caminho lê P+0x04/P+0x08 antes da decisão de deletar.
5. **ISOHEAP REFUTADO nesta era**: MALLOC_HEAP_BREAKDOWN=0 (PlatformEnable.h:567-568)
   → FastMalloc comum; libpas PS5 com PAS_ENABLE_ISO=0 (pas_config.h:68-75);
   segregação real = SIZE-CLASS em páginas 16KB (pas_internal_config.h:40-41).
   ⇒ StyleRuleFontFace (16B) clusteriza em páginas de size class 16 (com
   qualquer objeto WebCore de 9-16B), banda PRÁTICA distinta das T-tables
   (KB-classes) e da W-island — mas SEM offset VM fixo.
   **Discriminante confiável de StyleRuleFontFace real em dump:
   u32@P+0x04 ∈ {0x00000005, 0x00000025} (m_type=5) E rc@P+0x00 ∈ {2,3} —
   não a banda de endereço.**
6. **Implicação p690**: alvo = pool size-class-16; morte prevista de HIT
   real = só rc==1; HIT rc≥2 = sobrevivência COM decremento observável
   (= primitive de leitura por delta). Ver cross-check com A4 §morte(ii).
