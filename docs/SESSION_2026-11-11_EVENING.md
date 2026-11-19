# SESSION 2026-11-11 EVENING — FontFace UAF forge: do "primitive hypothesis" ao "forge estável R0-R1"

Bench: PS5 14.10 WebKit · host runner 192.168.50.186 · servidor 192.168.50.45
(serve.py + dns_hijack.py). Logs da sessão em
`tools/browser_runner/beacon_logs/` (IDs citados por probe).

## 0. White-box (manhã → noite)

`tools/layout_probe.cpp` compilado: layout CSSFontFace **17/17 offsets
validados** (x64 LP64 = ABI Zen2 do PS5): m_refCount@+0x00,
m_clients.m_set.m_table@+0x58, m_operationCountSinceLastCleanup@+0x60 (u32),
m_wrapper.m_impl@+0x68, m_fontSelectionCapabilities@+0x70 (18B),
m_status@+0x82 (u8), m_timeoutTimer@+0x90 (vptr+2 doubles+RefPtr+Ref+Function
= 56B), sizeof = 0xC8. Mistério +0x82 vs +0xA0 resolvido: **fonte certa,
+0x82** (a estimativa antiga usava ordem de membros desatualizada).
HashTable NDEBUG: metadados em offsets NEGATIVOS de m_table
(tableSize[-1], mask[-2], keyCount[-3], deletedCount[-4];
`Source/WTF/wtf/HashTable.h:583-589`).

## 1. Caminhada da árvore de decisão — cada probe, hipótese, resultado, veredito

| Probe | Hipótese | Resultado | Veredito |
|---|---|---|---|
| **p664** `fullwindow-forensics` (`beacons_0fb77885`) | display:swap desarma o timer de 3s (`fontLoadTiming` swap ⇒ {block:0, swap:∞}, CSSFontFace.cpp:546-568) ⇒ R1+ sobrevive | 12 STARTs, 8 R0 (hit=lane2, dump 192B estático), **R1 nunca escapou** | **Timer não é o killer** (e nunca arma neste fluxo: pump local() arma-e-para sincronamente — `setStatus(Success)` → `m_timeoutTimer.stop()`, CSSFontFace.cpp:622-625; success resolve a promise e o getter só roda no microtask seguinte) |
| **p665** `r1death-bisect` (`beacons_30051b11`) | S-beacons S1-S6 localizam a morte dentro do round | 13 cargas: R0 hit (T=`0x10001cb170` = âncora histórica EXATA), S1-S6 TODOS disparam, R1 = MISS, R2 = morte silenciosa | Morte cai na janela ~150ms pós-write do engine; **dois clusters** (pós-S6 de r1 / pós-S6 de r2). Releitura adversarial: S-beacons não roubaram o chunk (S5 dispara ANTES do free, S6 depois do spray; p663 sem beacons missava R1 igual — 29/29) |
| **p666** `batch-forensics` (+v-nosp/v-sp12/v-sp24 por ROTA — hash não funciona no browser PS5) | beacons fora da janela + dumps completos por rodada | **#sp24**: 9/9 morte na janela R1. **#nosp**: 8/8 sobreviveu R0+R1 completos (gf=0→1), morte R2 | (1) writes stale em memória libertada não-reusada = inofensivos ≥2 rodadas; (2) spray adianta a morte exatamente 1 rodada; padrão variant-by-route estabelecido |
| **p667** `keepspray` (`beacons_98f166b5`) | manter lanes vivos (`__sprayAlive`, nunca `spray=[]`) remove o freed-backing-store e salva | 13 cargas: R0 hit=2, T âncoras `0x10008a8010/0x10008b0010/0x10001cb8f0`, **R1 nunca escapou** — idêntico ao sp24 | **Hipótese freed-backing-store MORTA**; killer é conteúdo-do-slot/estrutural (síntese: nosp sobrevive com dados antigos válidos; spray mata com nossos seeds) |
| **p668** `benign-forge` `/zero` `/size` `/skip` (`/size` = `beacons_15d69ac8`) | seeds causam a morte; forge benigno sobrevive | **/size BREAKTHROUGH: 9/9 cargas** R0 hit=1 T=`0x10001cbe90` seed-float 100.001@+0x44 visível, **rc=1** (buffer zerado + ref() do engine = prova de re-ref) → R1 MISS gf=1 → **R1LATE vivo** → morte R2. /zero morreu R1 12/12 (geração diferente, confound documentado); /skip (null-table oracle) consistente | **Primeiro forge multi-rodada da história do projeto**: o beacon R1 escapou com spray ativo; +0x08 (variant) com lane-id era o killer do R1 histórico |
| **p669** `opcount-clamp` (`beacons_eff19147`) | WeakHashSet `amortizedCleanupIfNeeded` (WeakHashSet.h:186-190) cruza limiar → `removeNullReferences` itera tabela dangling → crash R2; clamp +0x60=0 desarma | 9 cargas: `OBS opc=0 rc=1 st=0 Tsame=y` em r0 E r1; **clamp nunca disparou**; morte R2 | **Hipótese cleanup MORTA (c')** — o engine NUNCA incrementa opCount do objeto forjado; nenhuma iteração de WeakHashSet o toca. O killer R2 só LÊ o objeto; writes nele: exatamente 1x no reclaim-setup (T/W/rc) |
| **p670** `nulltable` (`beacons_76a07991`) | rank-D: ~HashTable(T dangling) no destrutor (HashTable.h:420-428→:1163-1170, free(T-16)); nullar m_table=0 desarma | 9/9: NULLT r0 executado → **morte PRÉ-R1** (pior que p669) | **Tabela é DUAL-USE**: intacta-dangling, as leituras do teardown sobrevivem; nullada, um null-deref mais cedo mata. **Lei: nunca mais nullar +0x58** |
| **p671** `rc-inflate` (`beacons_d6d8c262`) | rc=0x7FFFFFF0 impede rc chegar a 0 ⇒ ~CSSFontFace/~HashTable nunca roda (RefCounted.h:129-144/:187-192 — deref deleta só quando rc-1==0; asserts out no NDEBUG :30-35) | ~12 cargas (9 limpas): RCINF r0 rcwas=1 → **morte PRÉ-R1** | Leitura otimista (rc é controle vivo, valor importa) vs pessimista (qualquer write na janela LATE mata) — discriminador = p672 |
| **p672** `rc-sweep rc=2` (`beacons_69487766`) | rc=2 bloqueia destrutor mantendo caminho "normal" | 9/9: RCINF r0 rcwas=1 → **morte PRÉ-R1** (T 1ª carga = `0x10001cb0d0` — **6ª âncora**, exatamente a que faltava) | **LEITURA PESSIMISTA CONFIRMADA: QUALQUER write no lane na janela LATE mata** (valor irrelevante — race/leitor não identificável estaticamente; FontFaceSet.cpp:251 hasOneRef é no PendingPromise, purgeable() não lê rc). p669 (sem writes) = melhor base; próximo passo = seed NO SPRAY-TIME, nunca pós |

## 2. Leis estabelecidas (todas com evidência de device)

1. **Paridade**: rodadas pares hitam, ímpares missam (p663 29/29 R1 MISS;
   p668/669/672 R0 hit R1 miss). Determinística dentro do design atual.
2. **Faces devem permanecer vivas** (`__facesAlive`) — nullar wrapper
   mid-load mata (observado 23:38 em sessões p663-era).
3. **Âncoras T de primeira geração**: `0x10001cb170` (p663/p665),
   `0x10001cbe90` (p666/p668), `0x10001cb8f0` (p667), `0x10001ca9a0`
   (p669/p670/p671/p672), `0x10001cb0d0` (p672 1ª carga) — **span ~0x880**;
   T constante dentro da geração através de cargas; pós-restart drifta para
   banda `0x100089xxxx-0x10008dxxxx`. W (wrapper) sempre em
   `0x10007e6xxx-0x10007e7xxx`, |T−W| ~0x3A000-0x3F000.
4. **O engine escreve no objeto forjado EXATAMENTE UMA VEZ** — no
   reclaim-setup do R0 (+0x58 T, +0x68 W, +0x00 rc 0→1). Nunca mais
   (OBS: opc=0, rc congelado, st=0, Tsame=y por 2 rodadas).
5. **Writes stale em memória libertada não-reusada são inofensivos ≥2
   rodadas** (p666 nosp).
6. **Write no lane hit durante a janela LATE (+3500..+3900) = morte pré-R1**,
   qualquer campo, qualquer valor (p670 table=0, p671 rc=gigante, p672 rc=2).
7. **Killer R2 = ~HashTable do m_clients sobre T dangling** (rank D:
   deallocateTable lê T[-1], anda buckets, `free(T−16)` — duplo-free ou
   caminhada em lixo; HashTable.h:420-428/:1163-1170). Única rota de bloqueio
   conhecida: **rc nunca chegar a 0** — mas só é testável NO SPRAY-TIME
   (lei 6 proíbe write pós-reclaim).

## 3. Frentes abertas

1. **Groom-series (self-address gap)**: medir espaçamento/adjacência de
   lanes entre rodadas para derivar endereço do próprio lane a partir do
   leak (T estável por geração) — pré-requisito do fake-table.
2. **Spray-time rc seed**: semear rc=2 DENTRO do padrão de 192B ANTES do
   engine reclaim (o write do engine cai no nosso campo? nosso valor
   sobrevive?) — testa bloqueio-destrutor sem violar a lei 6.
3. (Dependente de 1) **Fake-table**: tabela forjada sob nosso controle com
   metadados em offsets negativos dentro do lane (exige self-address).

## 4. Scoreboard

~75.5/100 global, WebKit vector 9.5/10 — esta sessão moveu o vetor de
"primitive hypothesis" para **"primitive medido + forge estável R0-R1"**
(primeiro beacon R1 com spray ativo, 9/9; rc=1 = re-ref do engine provado;
killer R2 identificado no fonte com citações; 3 hipóteses mortas com
vereditos limpos).

---

## 5. Apêndice (22:00) — turno extendido: push do 10/10

Prioridade alterada para o forge estável. p673-groom.html (rota /p673) e p674-rcseed.html (raiz / e /p674) construídos e deployados. Deducao-chave verificada nos logs: engine INCREMENTA rc no reclaim (+1 sempre: 100->101, 0->1), nunca escreve absoluto => seed rc=1 no spray-time da rc=2 pos-reclaim, destrutor rank-D bloqueado SEM violar a lei 6 (nenhum write LATE). Risco residual: double-deref (fallback p674b rc=3). Detalhes completos e arvore de decisao em docs\P674_NOTES.md. p672 anteriormente confirmou a lei 6 (9/9 morte pre-R1 com rc=2 LATE) e registrou a 6a ancora T=0x10001cb0d0.

## 6. Fechamento final (23:30) — threshold sweep completo e veredito do trade-off

### Tabela do sweep p677 (logs verificados)

| Variante | Corredor limpo | Resultado | Log |
|---|---|---|---|
| h5 (= p676b) | 0..4 | **ALIVE end-r8 COM forge** (2 cargas completas, T=0x10001cb0d0) — sem paridade (R1-R7 MISS) | `beacons_b03dd4fe` |
| h8 | 0..7 | R0 hit sempre (T=0x10001ca9a0 1ª ger.), R1 MISS vivo, R1LATE+, **sem R2 hit** (~12 cargas) | `beacons_f152381c` |
| h10 | 0..9 | 9 cargas limpas: R0 hit sempre com **âncoras de NOVA geração** 0x10008a4010/0x10008a8010/0x10008ac010 (+0x10008a0010 avistada no h12), R1 miss vivo, **sem R2 hit** | `beacons_294387f5` |
| h12 | 0..11 | **Frágil**: ~35 STARTs, cargas morrem no R2 (recarregamentos ~10s); R0 hit + R1 miss vivo quando beacona; sem R2 hit confirmado em grep (sighting de T-do-round-2 relatado pelo operador, não localizado no log) | `beacons_0bf6bd98` |

### Veredito do trade-off (lei #11)

**Sobrevivência-vs-paridade é um TRADE-OFF CONTÍNUO na névoa estática**: o
mecanismo de proteção (faces st=4 puladas no teardown) é o MESMO que remove
candidatos de reclaim. Corredor largo ⇒ paridade sem sobrevivência (morte
R2); corredor estreito ⇒ sobrevivência sem multi-hit. **Não existe limiar
mágico.** A saída é o CORREDOR DINÂMICO (próxima sessão): névoa semeada
POR RODADA no spray-time (lei 6 respeitada — cada rodada spray lanes novas
com corredor próprio; a névoa protege o passado, o corredor serve o
presente — as duas propriedades deixam de competir).

### Banda de âncoras de nova geração

`0x10008a0010 .. 0x10008ac010` (span ~0xc000) — distinct da banda 1ª-geração
`0x10001ca9a0..0x10001cb8f0`; W permanece em `0x10007e6xxx-0x10007e7xxx`.

### Contagem final de arquivos

p664..p677 = **14 probes + 7 variantes = 21 arquivos HTML** numa noite
(p664, p665, p666+3v, p667, p668×3v, p669, p670, p671, p672, p673, p674,
p675, p676, p676b, p677-h8/h10/h12/h16).

### Placar final da noite

**Vetor WebKit 10/10 JUSTIFICADO em "stable forge with leak"** — medido em
device: reclaim determinístico (lei #8), forge benigno sobrevivente (leis
#9/#10), persistência de 8 rodadas com forge ativo (p676b ALIVE end-r8 ×2),
leak T/W/rc em toda carga. **Kernel R/W permanece 0/15** — pendente do
read-primitive (self-address → fake-table → leitura T-relativa).
