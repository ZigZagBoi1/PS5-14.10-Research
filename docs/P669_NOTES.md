# P669 NOTES — op-count clamp (2026-11-11 21:20)

## BREAKTHROUGH — p668 /size (log `beacons_15d69ac8`)

9 cargas limpas (21:12:40 → 21:14:31), TODAS com o mesmo perfil completo:

```
R0 hit=1 T=0x10001cbe90 rc=1 opc=0 st82=0 gf=0 seed=100.001
  R0DUMP1 0:0000000000000001,40:42c8008300000000,58:...1cbe90,68:...
R0LATE alive changed=no
R1 MISS gf=1          <- getter disparou, lei da paridade manteve
R1LATE alive          <- PRIMEIRA VEZ que o beacon R1 escapou com spray ativo
(silêncio -> morte na janela do R2)
```

- O float benigno `100.001` visível no dump (`40:42c8008300000000` = float
  100.001 @+0x44 dentro do qword +0x40) prova que o lane forjado é NOSSO
  buffer e que o engine o re-referenciou: **rc=1** (buffer zerado + `ref()`
  do engine no add = exatamente 1 — antes, com seed 100, rc=101).
- O forge benigno sobreviveu à iteração de teardown do round 2 — a tese
  "conteúdo era o assassino" (topo: `m_propertiesOrCSSConnection` +0x08 com
  lane-id 2) sai fortalecida.
- **Confound honesto**: `/zero` morreu no R1 (12/12) mas em geração de
  WebProcess diferente (T=`0x10001cbe40` vs `be90`); o único delta
  zero↔size é o float. Não over-interpretar ainda — p669 mantém o seed
  /size (config conhecida-sobrevivente).

## HIPÓTESE DO KILLER R2 — WeakHashSet amortized cleanup (citações)

`m_clients` é `WeakHashSet<Client>`; layout validado: `m_set.m_table` @+0x58,
`m_operationCountSinceLastCleanup` (mutable unsigned) @+0x60.

| Mecanismo | Citação |
|---|---|
| iterador `operator++` incrementa o contador | `Source/WTF/wtf/WeakHashSet.h:65-69` |
| `contains()` incrementa | WeakHashSet.h:120-128 |
| `add()` chama o check de cleanup | WeakHashSet.h:98-103 |
| limiar: `currentCount / 2 > m_set.size()` → `removeNullReferences()` | WeakHashSet.h:186-190 |
| `removeNullReferences` = `m_set.removeIf(...)` ITERA a HashTable em `m_table` + zera contador | WeakHashSet.h:180-183 |
| `m_set.size()` lê keyCount em `m_table[-3]` (metadados em offsets negativos NDEBUG) | `Source/WTF/wtf/HashTable.h:585-598` |

Cadeia: T (@+0x58) é a tabela de clients ANTIGA da face libertada (alocação
separada, dangling). O teardown do round 2 itera clients via ref stale
(`iterateClients` — `CSSFontFace.cpp:55-61`, `copyToVectorOf<Ref<Client>>`)
→ ops acumulam no NOSSO +0x60 → limiar cruza → `removeIf` anda na tabela
dangling → deref de lixo → crash na janela R2.

**Alavanca**: o contador vive no NOSSO buffer → clamp +0x60 = 0 a cada
rodada (fora de toda janela crítica) desarma o cleanup para sempre.

## Design p669 (`probes/phase13_webkit/p669-clamp.html`)

Base = p668v-size exato (seed float @+0x44, keepspray `__sprayAlive`,
beacons batch, DUMP1/DUMP2, ROUNDS=8, todos os campos). DOIS deltas:

1. **OBS** (leitura cross-round): o lane hit do R0 fica vivo; cada
   `analyzeEarly` e `analyzeLate` emite
   `OBS r<N> opc=<v> rc=<v> st=<v> Tsame=<y/n>` — evolução natural do objeto
   forjado (o opCount cresce de verdade por rodada?).
2. **CLAMP** (escrita): em cada `analyzeLate`, DEPOIS do OBS (ler primeiro,
   escrever depois), zera +0x60 (e +0x64 defensivamente) em TODO lane hit
   rastreado (R0 + hits posteriores). Emite `CLAMP r<N> lane=<tag>
   opc-was=<v>` quando clampou valor não-zero.

## Árvore de decisão

```
6 cargas de /p669 (= raiz):
(a) ALIVE end-r8 (SUMMARY+ALIVE)
    => forge multi-rodada ESTÁVEL desbloqueado. O OBS diz a taxa real de
       crescimento de opCount por rodada; next: telemetria de groom x8
       rodadas (dataset groom-distance) e forge dirigido (escritas
       T-relativas) sobre o objeto estável.
(b) morte desloca para R3/R4
    => clamp ajudou parcialmente: cleanup é UM killer mas não o único.
       Contar rodadas ganhas vs /size (morte R2): 1 rodada = ~1 killer
       componente; ajustar p670 (clamp mais frequente: por analyzeEarly
       também) antes de concluir.
(c) morte AINDA no R2:
    (c') OBS mostrou opc=0 o tempo todo => opCount nunca cresceu; hipótese
         de cleanup MORTA neste fluxo — pivotar para FontFaceSet
         promise/face-vector (m_pendingPromises / faces Vector) e para a
         própria iteração begin()/skipEmptyBuckets (get<T> em cada bucket).
    (c'') OBS mostrou opc>0 crescendo => cleanup arma mas o clamp não
         segurou: o crescimento INTRA-rodada (entre LATE e a morte) cruza o
         limiar sozinho — clamp também no analyzeEarly (p670).
```

## Protocolo

1. serve.py restartado; `/` e `/p669` servem p669-clamp; `/zero /size /skip
   /p666 /p667 /nosp /sp12` preservados.
2. **6 cargas de `https://192.168.50.45/`** — **≥32 s por carga** (ROUNDS=8,
   8×~3,75 s) antes de recarregar.
3. Grep do log: `P669-OBS` (crescimento de opCount), `P669-CLAMP`
   (clamps efetivos), `P669-R2`/`R3`/`R4` (posição da morte),
   `SUMMARY`/`ALIVE end-r8-clamp` (sobrevivência total).
