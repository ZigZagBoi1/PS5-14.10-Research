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
4. **Semântica do discriminant**: index @ +0x0C (u32). 0 = properties
   (benigno), 1 = connection (o caminho ativo). Dump p685: hi-word=1 em
   nosso seed (erro de high-word corrigido) — engine leu index=1 e foi
   pelo caminho connection. Coexistiu com T/W/rc sem crash.
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
- [ ] Confirmar sizeof(StyleRuleBase)+0x00 rc layout (source) para
      prever rc-armor landing em lane.
- [ ] Simulador: emular HashMap::remove walk (bucket compare) + deref
      para validar previsões hit/miss antes da bancada.
