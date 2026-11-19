# P670 NOTES — null-table bisect (2026-11-11 21:25)

## Evidência p669 (log `beacons_eff19147`) — hipótese do cleanup MORTA

9 cargas limpas, TODAS: `R0 hit=1` (T=`0x10001ca9a0` — **5ª âncora de
primeira geração**; banda primeira-geração agora `0x10001cb170 / be90 /
cb8f0 / ca9a0` — span ~0x980; W estável `0x10007e6890-6cb0`; rc=1; seed
100.001) → `OBS opc=0 rc=1 st=0 Tsame=y` (r0 E r1) → `R1 MISS gf=1` →
`R1LATE alive` → morte na janela R2. **Clamp nunca disparou** — opCount
nunca se moveu.

**Veredito (c')**: hipótese amortizedCleanup MORTA — nenhuma iteração de
WeakHashSet toca o objeto forjado (o iterador/deref lê clients de faces
VIVAS, não da forjada). O killer do R2 só LÊ o objeto forjado; únicos writes
já observados nele: `+0x58` T, `+0x68` W, `+0x00` rc=1 — todos no
reclaim-setup do R0.

## Ranking A-D (com citações) — veredito: **D é o killer**

Ordem de destruição de `~CSSFontFace` (membros CSSFontFace.h:183-205,
destruição reversa): `m_timeoutTimer` → `m_wrapper` → `m_clients` →
`m_sources` → `m_ranges` → `m_families` → `m_propertiesOrCSSConnection`
(último).

| Rank | Candidato | Destrutor | Citação | Veredicto |
|---|---|---|---|---|
| **D** | **`m_clients` WeakHashSet → ~HashTable** | `if (m_table) deallocateTable(m_table)` | HashTable.h:420-428 | **LETAL**: deallocateTable (HashTable.h:1163-1170) lê `size = T[-1]` (tableSizeOffset −1, :585), anda buckets chamando `~ValueType()`, e `HashTableMalloc::free(T − 16)` (metadataSize 16, :589). T = tabela dangling → OU duplo-free do bloco 80B (ainda vivo em outro dono; alocado via zeroedMalloc metadataSize+size, :1147-1156) OU caminhada em lixo com `T[-1]` corrompido. **Letal nos dois ramos; única escape: `m_table == 0`** (`if (m_table)` falha → pula tudo). |
| A | variant `m_propertiesOrCSSConnection` (~Ref deref) | `~Ref() { if (ptr) ptr->deref(); }` | Ref.h:54-62 | **Benigno no nosso forge**: com buffer /size, +0x08 = 0 → `if (ptr)` falha → nada. (Com seeds antigos lane-id=2, deref de 0x2 — este era o killer do R1 histórico, já eliminado pelo forge benigno.) |
| B | `m_families` RefPtr | `derefIfNotNull(exchange(m_ptr, nullptr))` | RefPtr.h:75 | **Benigno**: null-check explícito; +0x18 = 0 no nosso forge. |
| C | `m_sources` Vector | `if (m_size) destruct(...)` | Vector.h:749-755 | **Benigno**: +0x48 = 0 → size 0 → nada; buffer inline-nulo não é liberado (sem malloc). |
| — | `m_timeoutTimer` | TimerBase dtor: stop() + `m_heapItem->clearTimer()` | Timer.cpp:262-272 | Benigno: timer inerte (arma-e-para síncrono no fluxo local(); ver P666_DESIGN §2); vptr no dtor não é chamado (dtor não-virtual do membro). |
| — | `m_wrapper` WeakPtr | trivial | WeakPtr.h:203-207 | Benigno. |

**Quem destrói a face forjada no teardown do round 2**: o wrapper `ff_r`
segura `Ref<CSSFontFace> m_backing` (FontFace.cpp:165-171) — vivo via
`__facesAlive`; a face FORJADA é a CSS-conectada (dono = cadeia
StyleRuleFontFace/stylesheet da rodada 0, já removida pelo getter com
`sty.remove()`). A atualização de estilo do round 2
(`updateStyleIfNeeded`, FontFaceSet.cpp:155) derruba a última referência
engine-side → `~CSSFontFace` roda NO BUFFER FORJADO → ~HashTable(T) detona.

## Intervenção p670 (`probes/phase13_webkit/p670-nulltable.html`)

Base = p669-clamp exata (seed /size, keepspray, OBS, clamp mantido por
paridade, batch beacons, ROUNDS=8). Delta: **NULLT** — após o OBS (ler
antes, escrever depois) em `analyzeEarly` E `analyzeLate` (o destrutor pode
rodar no teardown ANTES da passada LATE), zerar `+0x58`/`+0x5C` (m_table
completo) em TODO lane hit rastreado (R0 + posteriores). Emite
`NULLT r<N> Twas=<hex>`. Idempotente; re-executa na LATE para capturar
re-stamps do engine entre passes.

Se `m_table == 0` quando `~HashTable` rodar → `:423 if (m_table)` falha →
deallocateTable inteiro pulado → destrutor totalmente benigno → página
sobrevive R2+.

**Efeito colateral documentado**: nullar m_table quebra o scanHit de rodadas
futuras para esses lanes (+0x58 é o detector) — MISSes pós-null são
artefato esperado, não sinal do engine; o scan da rodada corrente ocorre
antes de o lane dela entrar em hitLanes.

## Árvore de decisão

```
6 cargas de /p670 (= raiz):
(a) ALIVE end-r8-nulltable
    => ~HashTable ERA o killer => STABLE FORGE ACHIEVED. Era do leak
       multi-rodada começa: p671 = telemetria de groom ×8 rodadas
       (dataset groom-distance com T/W/rc/lane por rodada num único
       WebProcess) e forge dirigido (escritas T-relativas).
(b) morte desloca p/ R3+
    => nulling ajudou parcialmente: outro deref de teardown resta (variant
       dtor com discriminante não-zero? engine re-stampa +0x58 depois do
       nosso NULLT — conferir OBS Tsame flip p/ 'n'). Contar rodadas ganhas
       vs p669 (R2): cada rodada = ~1 componente morto no caminho.
(c) morte ainda no R2
    => OU o destrutor não é o killer (hipótese morta) OU o engine re-stampa
       T entre NULLT e o dtor (OBS Tsame='n' revela). Próximo: substep
       beacons S1-S6 apenas nas rodadas >=2 (padrão p665, fora da janela
       crítica por design batch) + forge de +0x08 com ponteiro VÁLIDO via W
       (W é leak conhecido em toda carga — apontar o variant para um bloco
       MutableStyleProperties vivível exige endereçamento; groom primeiro).
```

## Protocolo

1. serve.py restartado; `/` e `/p670` servem p670-nulltable; `/p669 /size
   /zero /skip /p666 /p667 /nosp /sp12` preservados.
2. **6 cargas de `https://192.168.50.45/`** — **≥32 s por carga** antes de
   recarregar.
3. Grep: `P670-NULLT` (quando/quantos nulos), `P670-OBS` (Tsame flips =
   re-stamps do engine), `P670-R2`/`R3`+ (posição da morte),
   `SUMMARY`/`ALIVE end-r8-nulltable` (**a vitória**).
