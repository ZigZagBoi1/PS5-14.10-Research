# P671 NOTES — rc-inflate (2026-11-11 21:40)

## Veredito p670 (log `beacons_76a07991`) — nulltable PIOROU

9 cargas limpas, TODAS: `R0 hit=1` (T=`0x10001ca9a0` de novo — âncora de
primeira geração consistente), rc=1, seed intacta → `R0LATE alive` →
`NULLT r0 Twas=00000010001ca9a0` executado → **morte ANTES de qualquer
beacon R1** (9/9). Comparação crítica: p669 (idêntico SEM nullT) tinha
`R1 MISS` + `R1LATE alive`, morte no R2.

**Conclusão — tabela dual-use**: o T dangling na verdade PROTEGIA. Com a
tabela intacta (freed-but-intact: metadados/buckets legíveis), as leituras
de teardown do engine sobrevivem; com `m_table = 0`, um caminho de
null-deref MAIS CEDO mata (entre o NULLT em t0+3500ms do round 0 e a
análise do round 1 — candidatos: lookup/contains no m_clients zerado,
iteração que assume tabela não-nula, ou re-stamp do próprio engine
encontrando 0). **Lição: nunca mais nullar +0x58.** O p670 também entrega
um dado novo: o engine LÊ a região m_clients/m_table do objeto forjado
entre os rounds (senão table=0 não mudaria nada) — leituras que só
sobrevivem com a tabela intacta.

## Hipótese rc-inflate — verificação no fonte (citações)

| Pergunta | Resposta | Citação |
|---|---|---|
| `deref()` deleta só quando rc-1==0? | Sim: `derefBase()` retorna `true` apenas se `m_refCount - 1 == 0`; `RefCounted<T>::deref()` chama o Deleter (delete) somente nesse caso | `Source/WTF/wtf/RefCounted.h:129-144` e `:187-192` |
| CSSFontFace é destruído por outro gatilho? | Não: `class CSSFontFace final : public RefCounted<CSSFontFace>` — sem unique_ptr, sem delete manual conhecido no fluxo; WeakPtr nunca destrói forte | `Source/WebCore/css/CSSFontFace.h:60`; `WeakPtr.h:203-207` (~WeakPtrFactory só limpa) |
| ASSERTs de refCount no NDEBUG? | Nenhum: `CHECK_REF_COUNTED_LIFECYCLE` = 0 fora de `ASSERT_ENABLED \|\| ENABLE(SECURITY_ASSERTIONS)`; os asserts de `ref()`/`derefBase()`/`hasOneRef()` estão todos dentro desse guard | `RefCounted.h:30-35`, `:42-49`, `:129-137` |
| Custo? | Leak do lane (rc nunca chega a 0 → objeto nunca deletado) — aceitável; lanes já são mantidos vivos via `__sprayAlive` | — |

**Intervenção**: RCINF na passada LATE (após OBS) de cada rodada: se
`rc < 0x40000000`, escrever `+0x00 = 0x7FFFFFF0` (u32) e `+0x04 = 0` em
todo lane hit rastreado. Emissão `RCINF r<N> rcwas=<v>`. Com rc gigante,
cada deref engine-side cai para huge-1 → delete NUNCA dispara →
`~CSSFontFace` → `~HashTable(T)` (o killer rank D, HashTable.h:420-428 →
:1163-1170) **nunca roda**. A tabela fica dangling-but-intact — o lado bom
do dual-use que o p670 provou ser obrigatório preservar.

**Experimento natural embutido**: o OBS lê rc a cada rodada. Se o engine
deref o rc inflado, OBS mostra `0x7FFFFFF0-N` (conta os derefs); se rc
permanecer congelado em `0x7FFFFFF0`, nenhum deref acontece (a destruição
estaria agendada por outro mecanismo → outcome (b)).

## Caveat adversarial (honesto)

rc-inflate bloqueia **apenas** o killer-destrutor. Se o teardown também
LÊ o objeto forjado de forma letal (ex.: `families()` → `properties()` →
switchOn-deref do variant +0x08 nulo — CSSFontFace.cpp:111-121; ou lookup
no m_clients com tabela reusada), a morte R2/R3 pode persistir por um
killer de leitura. A morte pré-R1 do p670 com table=0 PROVA que algum read
do engine toca a região clients/table entre rounds; com T intacto esses
reads sobrevivem (evidência p668/669), então o destrutor continua sendo o
suspeito primário do R2 — mas (b) na árvore cobre a alternativa.

## Árvore de decisão

```
6 cargas de /p671 (= raiz):
(a) ALIVE end-r8-rcinf (SUMMARY + ALIVE)
    => KILLER-DESTRUTOR NEUTRALIZADO + STABLE FORGE. Telemetria multi-rodada
       completa desbloqueada: p672 = dataset groom-distance ×8 rodadas num
       único WebProcess (T/W/rc/lane/dirtyNear por rodada) e forge dirigido.
(b) morte no R2 de novo
    => OU destruição ignora refcount (cadeia de posse direta — verificar
       OBS rc congelado) OU killer de leitura (variant deref). Pivot:
       forge de +0x08 com ponteiro VÁLIDO (precisa VA — groom/W-derivado)
       ou substep beacons S1-S6 nas rodadas >=2 (padrão p665).
(c) morte pré-R1 (fenótipo p670)
    => a escrita do rc em si quebrou um leitor (algo parseia rc durante a
       iteração de teardown) — OBS/dump mostraria; revert para p669 exato
       e re-baseline.
```

## Protocolo

1. serve.py restartado; `/` e `/p671` servem p671-rcinflate; `/p670 /p669
   /size /zero /skip /p666 /p667 /nosp /sp12` preservados.
2. **6 cargas de `https://192.168.50.45/`** — **≥32 s por carga** antes de
   recarregar.
3. Grep: `P671-RCINF` (rcwas — de 1 para 0x7FFFFFF0), `P671-OBS`
   (sequência de rc através dos rounds: decrementa = engine deref;
   congelado = nenhum deref), `P671-R1/R2/R3` (posição da morte),
   `SUMMARY`/`ALIVE end-r8-rcinf` (**a vitória**).
